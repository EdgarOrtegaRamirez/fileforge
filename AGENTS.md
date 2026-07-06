# AGENTS.md — FileForge

## Project Overview
**FileForge** is a universal binary analysis toolkit written in Rust. It provides 9 CLI subcommands for analyzing files at the byte level: magic-byte type detection (100+ signatures), Shannon entropy analysis with encryption/compression heuristics, byte-frequency histograms, encoding detection (UTF-8/16/32, BOM), annotated hex dumps, file comparison via cosine similarity, batch directory scanning, and metadata inspection.

## Tech Stack
- **Language:** Rust 2021
- **CLI Framework:** clap 4.6 (derive mode)
- **Serialization:** serde 1.0 + serde_json 1.0 + chrono 0.4 + csv 1.3
- **Tests:** `cargo test` (48 unit tests across all modules)

## Project Structure
```
fileforge/
├── Cargo.toml          # Project metadata and dependencies
├── src/
│   ├── main.rs         # CLI entry point (9 subcommands via clap derive)
│   ├── lib.rs          # Library root, re-exports all modules
│   ├── magic.rs        # Magic-byte file signature database (~100 signatures)
│   ├── entropy.rs      # Shannon entropy, windowed scanning, detection
│   ├── frequency.rs    # Byte frequency histograms & classification
│   ├── encoding.rs     # BOM detection, encoding heuristics
│   ├── hexdump.rs      # Hex dump generation (basic, annotated, compact)
│   └── compare.rs      # File comparison (entropy profiles, frequency cosine sim)
├── tests/              # (future integration tests)
├── README.md
├── LICENSE
├── AGENTS.md           # This file
├── SECURITY.md         # Security notes
└── .github/workflows/ci.yml
```

## Build & Test
```bash
cargo build          # Compile
cargo test           # Run all 48 unit tests
cargo fmt            # Format code
cargo clippy         # Lint
```

## Key Design Decisions
1. **Manual `serde::Serialize` for `ByteFrequency`** — `[u64; 256]` does not derive Serialize in serde.
2. **Removed empty-magic signatures** (BSON empty doc `\x00\x00\x00\x00`, TOML empty) — they matched all-zero test data and broke `test_no_match`.
3. **Cosine similarity returns 1.0 for zero vectors** — empty files are semantically "identical".
4. **No `--compact` CLI flag** — compact mode exists in the library but is not exposed via CLI (added to annotated mode `-a`).
5. **`detect` command** prioritizes specificity: checks signatures from longest magic to shortest.

## Testing Strategy
- Every module has its own `#[cfg(test)] mod tests` block.
- Tests cover: happy path, empty input, edge cases (max entropy, all zeros, all 0xFF), and specific file types.
- `test_no_match` ensures that bytes with no matching signature return `None`.
- `test_compare_empty` ensures cosine similarity is 1.0 for two empty files.

## Common Pitfalls
- **Don't add signatures with empty magic (`b""`)** — they match everything.
- **Don't add signatures with very short/generic magic** (e.g., 4 null bytes) — they produce false positives.
- **Always run `cargo fmt`** before committing — the formatter catches trailing whitespace and formatting inconsistencies.
- **BSON entries** — be careful with BSON signatures that have overlapping magic bytes.

## Dependencies
- `clap` 4.6 — CLI framework (derive mode)
- `serde` 1.0 + `serde_json` 1.0 — JSON serialization
- `chrono` 0.4 — Timestamp formatting
- `csv` 1.3 — CSV output for scan results

## Future Enhancements
- File carving (extract embedded files by signatures)
- Entropy heatmaps (windowed entropy visualization)
- More magic signatures (add from file:///usr/share/misc/magic)
- Streaming mode for very large files
- Custom signature definitions (TOML config file)
