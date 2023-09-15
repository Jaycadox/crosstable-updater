use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::process::exit;
use clap::Parser;
use regex::Regex;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the old crossmap
    #[arg(short, long)]
    map: String,

    /// Path to the generated crosstable
    #[arg(short, long)]
    table: String,

    /// Output file
    #[arg(short, long)]
    out: String,
}

fn get_file_content(query: &'static str, path: PathBuf) -> String {
    if !path.exists() {
        println!("Error reading {query}, path does not exist: {}", path.display());
        exit(1);
    }

    std::fs::read_to_string(path).expect("Unable to read file")
}

fn main() {
    let args = Args::parse();
    let crossmap = get_file_content("crossmap",  args.map.into()).to_lowercase();
    let crosstable = get_file_content("crosstable", args.table.into()).to_lowercase();
    let re = Regex::new("0x([0-9a-fA-F]+)[|, :]+0x([0-9a-fA-F]+)").expect("Invalid regex expr");

    let mut crosstable_map = HashMap::new();
    for m in re.captures_iter(&crosstable) {
        let (old, new) = (m.get(1).unwrap().as_str(), m.get(2).unwrap().as_str());
        let (old, new) = (u64::from_str_radix(old, 16).unwrap(), u64::from_str_radix(new, 16).unwrap());
        crosstable_map.insert(old, new);
    }

    let mut crossmap_map = HashMap::new();
    let mut failed_mappings = 0;
    for m in re.captures_iter(&crossmap) {
        let (old, new) = (m.get(1).unwrap().as_str(), m.get(2).unwrap().as_str());
        let (old, new) = (u64::from_str_radix(old, 16).unwrap(), u64::from_str_radix(new, 16).unwrap());
        crossmap_map.insert(old, *crosstable_map.get(&new).unwrap_or_else(|| {
            failed_mappings += 1;
            return &0;
        }));
    }

    let mut file = File::create(args.out).expect("Unable to create output file");
    let mut buf = String::new();
    for (old, new) in crossmap_map {
        buf.push_str(&format!("0x{:X}, 0x{:X}\n", old, new));
    }
    file.write_all(buf.as_bytes()).expect("Failed to write file");
    println!("Done. {failed_mappings} failed mapping/s.");
}