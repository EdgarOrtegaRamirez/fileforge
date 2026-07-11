# FileForge

**Universal Binary Analysis Toolkit** — A fast, zero-dependency (beyond CLI framework) command-line tool for inspecting, analyzing, and comparing files at the byte level.

[![CI](https://github.com/EdgarOrtegaRamirez/fileforge/actions/workflows/ci.yml/badge.svg)](https://github.com/EdgarOrtegaRamirez/fileforge/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/Rust-2021-blue.svg)](https://www.rust-lang.org/)

## Features

|| Command | Description |
||---------|-------------|
|| `detect` | Identify file types using 100+ magic byte signatures |
|| `entropy` | Shannon entropy analysis with encryption/compression detection |
|| `frequency` | Byte frequency histograms and content classification |
|| `encoding` | Detect text encodings (UTF-8, UTF-16, UTF-32, ASCII) |
|| `hexdump` | Hex dumps with ASCII view and byte-type annotations |
|| `compare` | Compare two files by entropy profiles and frequency vectors |
|| `analyze` | Complete file analysis (combines all modules) |
|| `scan` | Batch directory scanning with CSV/JSON output |
|| `strings` | Extract printable strings from binary files |
|| `info` | File metadata (size, timestamps, permissions) |

## Quick Start

### Install

```bash
# From source
git clone https://github.com/EdgarOrtegaRamirez/fileforge.git
cd fileforge
cargo install --path .

# Or directly from crates.io (when published)
cargo install fileforge
```

### Usage

```bash
# Detect file types
fileforge detect photo.jpg document.pdf video.mp4

# Full analysis of a file
fileforge analyze mystery_file.bin

# Check if a file might be encrypted
fileforge entropy --threshold 7.0 suspicious.enc

# Compare two executables
fileforge compare old_app new_app

# Batch scan a directory
fileforge scan /path/to/files --format json --output results.json

# Hex dump with annotations
fileforge hexdump --annotated --length 256 firmware.bin

# Extract printable strings from a binary
fileforge strings mystery.bin

# Extract strings with UTF-16LE support and show offsets
fileforge strings --unicode --show-offset firmware.bin

# Extract strings as JSON
fileforge strings --json --min-length 8 binary.bin
```

## Architecture

```
src/
├── main.rs          # CLI entry point with 9 subcommands
├── lib.rs           # Library root, re-exports all modules
├── magic.rs         # 100+ file signature database (magic bytes)
├── entropy.rs       # Shannon entropy, windowed scanning, detection heuristics
├── frequency.rs     # Byte frequency analysis, classification
├── encoding.rs      # BOM detection, encoding heuristics
├── hexdump.rs       # Hex dump generation with annotations
└── compare.rs       # File comparison (entropy + frequency similarity)
```

### Design Principles

- **Performance**: Written in Rust for maximum speed on large files
- **Comprehensive**: 100+ file type signatures covering common formats
- **Extensible**: Module-based architecture — easy to add new analysis techniques
- **Safe**: No unsafe code, proper error handling throughout
- **Output Formats**: JSON and human-readable formats for scripting

## File Type Detection

FileForge detects 100+ file types using magic byte signatures:

- **Images**: PNG, JPEG, GIF, BMP, TIFF, WebP, ICO, HEIC
- **Documents**: PDF, DOCX, PPTX, XLSX, ODT, RTF, EPUB
- **Archives**: ZIP, GZIP, TAR, BZ2, XZ, 7Z, RAR
- **Media**: MP3, MP4, MKV, AVI, FLAC, OGG, WAV
- **Executables**: ELF, PE, Mach-O, WASM
- **Data**: JSON, XML, CSV, SQLite, SQLite3
- **Code**: JavaScript, Python, Rust, C, Go, Java, TypeScript
- **Crypto**: PGP/GPG keys and signatures
- **Network**: PCAP captures
- **Scientific**: NetCDF, HDF5

## Entropy Analysis

Shannon entropy ranges from 0.0 (empty/uniform) to 8.0 (maximum randomness):

| Entropy Range | Classification | Typical Content |
|---------------|----------------|-----------------|
| 0.0 – 2.0 | Very Low | Mostly null bytes, simple headers |
| 2.0 – 4.0 | Low | Structured data, source code |
| 4.0 – 6.0 | Medium | Mixed content, compressed text |
| 6.0 – 7.0 | High | Compressed data, encrypted content |
| 7.0 – 8.0 | Very High | Encryption, compression, random data |

The `entropy` command also detects:
- **Encryption** (high entropy throughout)
- **Compression** (high entropy with structure)
- **Structured data** (low entropy with patterns)

## JSON Output

All commands support `--json` flag for machine-readable output:

```bash
fileforge detect --json photo.jpg
fileforge analyze --json firmware.bin
fileforge scan --format json /path/to/files
```

## Examples

### Detect file types in current directory
```bash
fileforge detect *
# Output:
# photo.jpg: JPEG image (image/jpeg, .jpg)
# document.pdf: PDF document (application/pdf, .pdf)
# backup.zip: ZIP archive (application/zip, .zip)
```

### Compare two binary files
```bash
fileforge compare firmware_v1.bin firmware_v2.bin
# Output:
# Similarity: 97.2%
# Entropy A: 6.8921 | Entropy B: 6.9034
# Frequency similarity: 98.1%
# Summary: Files are very similar
```

### Batch scan with JSON output
```bash
fileforge scan ./downloads --format json --output scan_results.json
```

## Configuration

No configuration needed — FileForge works out of the box. For custom magic signatures or analysis parameters, edit `src/magic.rs` and recompile.

## Security

- No network calls — all analysis is local
- No file writes — read-only operations
- Safe path handling — no path traversal vulnerabilities
- Input validation on all file operations

## Contributing

Contributions welcome! Areas where help is needed:
- Additional magic byte signatures
- New analysis modules (file carving, entropy mapping)
- Performance optimizations for very large files
- Cross-platform testing

## License

MIT — see [LICENSE](LICENSE) for details.
