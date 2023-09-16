use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::exit;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use clap::Parser;
use enum_index::EnumIndex;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use ysc_utils::disassemble::Instruction;
use ysc_utils::ysc::YSCScript;

fn get_dir(query: &'static str) -> PathBuf {
    print!("Enter {query} path: ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .expect("Unable to read line");
    let pb = PathBuf::from(line.replace(['\r', '\n'], ""));
    if pb.exists() {
        pb
    } else {
        panic!("specified directory does not exist")
    }
}

fn get_ysc_paths(path: &Path) -> Vec<PathBuf> {
    let mut vec = vec![];
    for file in path.read_dir().expect("invalid path") {
        let file = file.expect("invalid file");
        let f_type = file.file_type().expect("cannot get file type");
        if f_type.is_dir() {
            vec.append(&mut get_ysc_paths(&file.path()));
        }

        let file_name = file.file_name();
        let file_name = file_name.to_str().unwrap_or_default();
        if file_name.ends_with(".ysc.full") || file_name.ends_with(".ysc") {
            vec.push(file.path())
        }
    }

    vec
}

fn get_progress_bar_template(query: String) -> ProgressStyle {
    ProgressStyle::with_template(&format!(
        "{query:25} [{{elapsed_precise}}] {{bar:60}} {{pos:>7}}/{{len:7}} {{msg}}"
    ))
    .expect("Invalid progress bar template")
    .progress_chars("##-")
}

fn get_scripts(query: &'static str, path: Option<String>) -> Vec<YSCScript> {
    let script = if let Some(path) = path {
        path.into()
    } else {
        get_dir(query)
    };

    let path_name_str = script.display().to_string();

    if path_name_str.ends_with(".ysc") || path_name_str.ends_with(".ysc.full") {
        println!("{query}: Please target a directory containing multiple .ysc(.full) files. The chosen directory is recursively searched.");
        exit(1)
    }

    let script_paths = get_ysc_paths(&script);

    if script_paths.len() == 1 {
        println!("{query}: Please target a directory containing multiple .ysc(.full) files. The chosen directory is recursively searched.");
        exit(1)
    }

    let pb = Arc::new(Mutex::new(ProgressBar::new(script_paths.len() as u64)));
    pb.lock()
        .unwrap()
        .set_style(get_progress_bar_template(format!("Loading {query}...")));

    let _ = std::io::stdout().flush();

    let ysc_scripts = Arc::new(Mutex::new(Vec::with_capacity(script_paths.len())));
    script_paths
        .par_iter()
        .for_each(|scr| match YSCScript::from_ysc_file(scr) {
            Ok(ysc_script) => {
                let pb = pb.lock().unwrap();
                pb.set_message(ysc_script.name.clone());
                ysc_scripts.lock().unwrap().push(ysc_script);
                pb.inc(1);
            }
            Err(e) => {
                println!("Failed to load script '{}': {e}", scr.display());
            }
        });
    pb.lock().unwrap().finish();

    Mutex::into_inner(Arc::try_unwrap(ysc_scripts).unwrap()).unwrap()
}

struct ScriptPair {
    old: YSCScript,
    new: YSCScript,
}

fn generate_pairs(old: Vec<YSCScript>, mut new: Vec<YSCScript>) -> Vec<ScriptPair> {
    let _ = std::io::stdout().flush();

    let mut vec = vec![];

    let mut non_matching = vec![];

    for old_script in old {
        let name = old_script.name.to_lowercase();
        if let Some(new_script_loc) = new.iter().position(|s| s.name.to_lowercase() == name) {
            vec.push(ScriptPair {
                old: old_script,
                new: new.remove(new_script_loc),
            })
        } else {
            non_matching.push(name);
        }
    }

    vec
}

#[derive(Debug, Clone)]
struct ThinNative {
    hash: u64,
    native_hash: u64,
    num_args: u8,
    num_return: u8,
}

fn generate_thin_natives(instructions: &[Instruction]) -> Vec<ThinNative> {
    let mut bytes = Vec::with_capacity(200);
    let mut native_calls = Vec::with_capacity(instructions.len() / 1000);

    for inst in instructions {
        if bytes.len() > 140 {
            bytes.drain(0..(bytes.len() - 140));
        }
        bytes.extend_from_slice(&inst.enum_index().to_le_bytes());
        match inst {
            Instruction::PushConstU8 { one } => bytes.push(*one),
            Instruction::PushConstU24 { num } => bytes.extend_from_slice(&num.to_le_bytes()),
            Instruction::PushConstU32 { one } => bytes.extend_from_slice(&one.to_le_bytes()),
            Instruction::PushConstF { one } => bytes.extend_from_slice(&one.to_le_bytes()),
            Instruction::Native {
                native_hash,
                num_args,
                num_returns,
                ..
            } => {
                let hash = t1ha::t1ha0(&bytes, Default::default());
                native_calls.push(ThinNative {
                    hash,
                    native_hash: *native_hash,
                    num_args: *num_args,
                    num_return: *num_returns,
                });
            }
            _ => {}
        }
    }

    native_calls
}

fn get_script_instructions(
    query: &'static str,
    ysc_script: &YSCScript,
    old_format: bool,
) -> Vec<Instruction> {
    let vec;
    let mut disasm = ysc_utils::disassemble::Disassembler::new(ysc_script);
    disasm.old_format = old_format;
    if let Ok(instructions) = disasm.disassemble(None) {
        vec = instructions.instructions;
    } else {
        println!("Error during disassembly of {query} scripts.");
        if !old_format {
            println!("Try again with the `--{query}-old-format` flag.");
        }
        exit(1);
    }

    vec
}

fn get_thin_natives(
    query: &'static str,
    ysc_script: &YSCScript,
    old_format: bool,
) -> Vec<ThinNative> {
    generate_thin_natives(&get_script_instructions(query, ysc_script, old_format))
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to a directory containing old .ysc scripts
    #[arg(short, long)]
    old: Option<String>,

    /// Path to a directory containing new .ysc scripts
    #[arg(short, long)]
    new: Option<String>,

    /// Path to a file where the crosstable gets put
    #[arg(short, long)]
    out: String,

    /// Use `old_format` for the old scripts
    #[arg(long, default_value_t = false)]
    old_old_format: bool,

    /// Use `old_format` for the new scripts
    #[arg(long, default_value_t = false)]
    new_old_format: bool,
}

fn main() {
    let args = Args::parse();

    let script_pairs = generate_pairs(
        get_scripts("old scripts", args.old),
        get_scripts("new scripts", args.new),
    );

    let total_len = script_pairs.len();
    let total_disassembled = std::sync::atomic::AtomicUsize::new(0);

    let old_natives = Arc::new(Mutex::new(HashMap::<u64, ThinNative>::new()));
    let new_natives = Arc::new(Mutex::new(HashMap::<u64, ThinNative>::new()));

    let pb = Arc::new(Mutex::new(ProgressBar::new(total_len as u64)));
    pb.lock()
        .unwrap()
        .set_style(get_progress_bar_template("Disassembling scripts...".into()));

    script_pairs.par_iter().for_each(|pair| {
        let old_ntvs = get_thin_natives("old", &pair.old, args.old_old_format);
        let old_ntvs_len = old_ntvs.len();
        {
            let mut old_natives = old_natives.lock().unwrap();
            for ntv in old_ntvs {
                old_natives.insert(ntv.hash, ntv);
            }
        }

        let new_ntvs = get_thin_natives("new", &pair.new, args.new_old_format);
        let new_ntvs_len = new_ntvs.len();
        {
            let mut new_natives = new_natives.lock().unwrap();
            for ntv in new_ntvs {
                new_natives.insert(ntv.hash, ntv);
            }
        }

        {
            let pb = pb.lock().unwrap();
            pb.set_message(format!(
                "{:>30}: {:>9} native calls",
                pair.old.name.to_lowercase(),
                old_ntvs_len + new_ntvs_len
            ));
            pb.inc(1);
        }

        total_disassembled.fetch_add(old_ntvs_len + new_ntvs_len, Ordering::AcqRel);
    });

    pb.lock().unwrap().set_message("Finding native pairs...");
    let old_natives = Mutex::into_inner(Arc::try_unwrap(old_natives).unwrap()).unwrap();
    let new_natives = Mutex::into_inner(Arc::try_unwrap(new_natives).unwrap()).unwrap();
    let total_natives = total_disassembled.load(Ordering::Relaxed);

    let mut matched_old_natives = HashMap::<u64, ThinNative>::new();
    let ideal = old_natives.len();
    for (hash, f) in old_natives.iter() {
        if new_natives.contains_key(hash) {
            matched_old_natives.insert(*hash, f.clone());
        }
    }
    pb.lock().unwrap().finish_with_message(format!(
        "{}/{} unique calls. {}/{} matched",
        old_natives.len() + new_natives.len(),
        total_natives,
        matched_old_natives.len(),
        ideal
    ));

    let mut crosstable = HashMap::<u64, u64>::new();
    let old_natives = matched_old_natives;

    print!("Generating crosstable...  ");
    let _ = std::io::stdout().flush();

    for (_, old_native) in old_natives {
        let new_native = new_natives
            .get(&old_native.hash)
            .expect("Could not find new version of function");

        if old_native.num_return == new_native.num_return
            && old_native.num_args == new_native.num_args
        {
            crosstable.insert(old_native.native_hash, new_native.native_hash);
        }
    }

    let mut file = File::create(&args.out).expect("Unable to create output file");

    let mut buf = String::new();
    let crosstable_len = crosstable.len();

    for (old, new) in crosstable {
        buf.push_str(&format!("0x{:X},0x{:X}\n", old, new));
    }
    file.write_all(buf.as_bytes())
        .expect("Unable to write to output file");
    println!("Wrote {} mappings to: '{}'", crosstable_len, args.out);
}
