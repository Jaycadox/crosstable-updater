# crosstable-updater
`crosstable-updater` contains two binaries: `crosstable_updater` and `crossmap_gen`.
## crosstable_updater
Given a folder containing multiple old YSC files, and a folder containing multiple new YSC files, it takes the native calls in the old scripts, and finds them in the new scripts, generating a crosstable.

Uses [ysc-utils](https://github.com/jaycadox/ysc-utils) under-the-hood.

## crossmap_gen
Given an old crossmap `(original : old)` and a crosstable `(old : new)`, it generates a crossmap `(original : new)`.

## Download
Pre-built binaries are collected as action workflow artifacts.

## Build
```sh
git clone https://github.com/Jaycadox/crosstable-updater
cd crosstable-updater
cargo build -r
```
