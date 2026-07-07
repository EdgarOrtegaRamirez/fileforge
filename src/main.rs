use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};

use fileforge::compare;
use fileforge::encoding;
use fileforge::entropy;
use fileforge::frequency;
use fileforge::hexdump;
use fileforge::magic;

#[derive(Parser)]
#[command(
    name = "fileforge",
    version,
    about = "Universal binary analysis toolkit — detect file types, compute entropy, analyze byte frequencies, and more"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Detect file type by magic bytes
    Detect {
        /// File to analyze
        #[arg(required = true)]
        files: Vec<PathBuf>,
    },

    /// Compute Shannon entropy and encryption detection
    Entropy {
        /// File to analyze
        file: PathBuf,
        /// Window size for sliding entropy analysis
        #[arg(short, long, default_value = "0")]
        window: usize,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Analyze byte frequency distribution
    Frequency {
        /// File to analyze
        file: PathBuf,
        /// Number of top bytes to show
        #[arg(short = 'n', long, default_value = "32")]
        top: usize,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Detect character encoding
    Encoding {
        /// File to analyze
        file: PathBuf,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Generate hex dump
    Hexdump {
        /// File to analyze
        file: PathBuf,
        /// Bytes per line (8, 16, 32)
        #[arg(short, long, default_value = "16")]
        width: usize,
        /// Annotated mode with type labels
        #[arg(short, long)]
        annotated: bool,
        /// Maximum bytes to dump (0 = all)
        #[arg(short = 'l', long, default_value = "512")]
        length: usize,
    },

    /// Compare two files by statistical properties
    Compare {
        /// First file
        file_a: PathBuf,
        /// Second file
        file_b: PathBuf,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Full analysis of a file (all modules combined)
    Analyze {
        /// File to analyze
        file: PathBuf,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Scan a directory for file types
    Scan {
        /// Directory to scan
        #[arg(default_value = ".")]
        dir: PathBuf,
        /// Maximum depth
        #[arg(short, long, default_value = "3")]
        depth: usize,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Show information about the magic byte database
    Info,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Detect { files } => cmd_detect(&files),
        Commands::Entropy { file, window, json } => cmd_entropy(&file, window, json),
        Commands::Frequency { file, top, json } => cmd_frequency(&file, top, json),
        Commands::Encoding { file, json } => cmd_encoding(&file, json),
        Commands::Hexdump {
            file,
            width,
            annotated,
            length,
        } => cmd_hexdump(&file, width, annotated, length),
        Commands::Compare {
            file_a,
            file_b,
            json,
        } => cmd_compare(&file_a, &file_b, json),
        Commands::Analyze { file, json } => cmd_analyze(&file, json),
        Commands::Scan { dir, depth, json } => cmd_scan(&dir, depth, json),
        Commands::Info => cmd_info(),
    }
}

fn cmd_detect(files: &[PathBuf]) {
    for file in files {
        let data = match std::fs::read(file) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("Error reading {}: {}", file.display(), e);
                continue;
            }
        };

        let detections = magic::detect_all(&data);
        if detections.is_empty() {
            println!(
                "{}: unknown file type (first 16 bytes: {})",
                file.display(),
                data.iter()
                    .take(16)
                    .map(|b| format!("{:02x}", b))
                    .collect::<Vec<_>>()
                    .join(" ")
            );
        } else {
            for d in &detections {
                println!(
                    "{}: {} ({}, {})",
                    file.display(),
                    d.file_type,
                    d.mime_type,
                    if d.extension.is_empty() {
                        "no extension".to_string()
                    } else {
                        format!(".{}", d.extension)
                    }
                );
            }
        }
    }
}

fn cmd_entropy(file: &PathBuf, window: usize, json: bool) {
    let data = match std::fs::read(file) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error reading {}: {}", file.display(), e);
            return;
        }
    };

    let ent = entropy::shannon_entropy(&data);
    let enc = entropy::detect_encryption(&data);

    if json {
        let output = serde_json::json!({
            "file": file.display().to_string(),
            "size": data.len(),
            "entropy": ent,
            "entropy_class": entropy::entropy_class(ent),
            "chi_squared": enc.chi_squared,
            "active_bytes": enc.active_bytes,
            "likely_encrypted": enc.likely_encrypted,
            "likely_compressed": enc.likely_compressed,
            "likely_structured": enc.likely_structured,
        });
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
    } else {
        println!("File: {}", file.display());
        println!("Size: {} bytes", data.len());
        println!("Entropy: {:.4} / 8.0", ent);
        println!("Classification: {}", entropy::entropy_class(ent));
        println!("Active byte values: {}", enc.active_bytes);
        println!("Chi-squared: {:.2}", enc.chi_squared);
        println!(
            "Encrypted: {} | Compressed: {} | Structured: {}",
            enc.likely_encrypted, enc.likely_compressed, enc.likely_structured
        );
    }

    if window > 0 && window < data.len() {
        let windows = entropy::windowed_entropy(&data, window);
        if !json {
            println!("\nWindowed entropy (window={}):", window);
            let step = (windows.len() / 20).max(1);
            for (_i, (offset, w_ent)) in windows.iter().enumerate().step_by(step) {
                let bar = "█".repeat((w_ent * 5.0) as usize);
                println!("  {:>8}: {:.4} {}", offset, w_ent, bar);
            }
        }
    }
}

fn cmd_frequency(file: &PathBuf, top: usize, json: bool) {
    let data = match std::fs::read(file) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error reading {}: {}", file.display(), e);
            return;
        }
    };

    let freq = frequency::ByteFrequency::from_bytes(&data);
    let class = freq.classify();

    if json {
        let top_bytes: Vec<_> = freq
            .top_n(top)
            .iter()
            .map(|(b, c, r)| {
                serde_json::json!({
                    "byte": format!("0x{:02x}", b),
                    "count": c,
                    "ratio": r,
                })
            })
            .collect();

        let output = serde_json::json!({
            "file": file.display().to_string(),
            "size": data.len(),
            "unique_bytes": freq.unique_bytes,
            "classification": class,
            "top_bytes": top_bytes,
        });
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
    } else {
        println!("File: {}", file.display());
        println!("Size: {} bytes", freq.total);
        println!("Unique byte values: {}", freq.unique_bytes);
        println!(
            "Likely text: {} | Likely binary: {} | Unicode: {}",
            class.likely_text, class.likely_binary, class.has_unicode
        );
        println!("\nTop {} byte values:", top);
        println!("{}", frequency::format_histogram(&freq, 40));
    }
}

fn cmd_encoding(file: &PathBuf, json: bool) {
    let data = match std::fs::read(file) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error reading {}: {}", file.display(), e);
            return;
        }
    };

    let enc = encoding::detect_encoding(&data);

    if json {
        let output = serde_json::json!({
            "file": file.display().to_string(),
            "encoding": enc.encoding,
            "bom": enc.bom,
            "confidence": enc.confidence,
            "valid_utf8": enc.valid_utf8,
            "pure_ascii": enc.pure_ascii,
            "null_percentage": enc.null_percentage,
        });
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
    } else {
        println!("File: {}", file.display());
        println!("Encoding: {}", enc.encoding);
        if let Some(bom) = &enc.bom {
            println!("BOM: {}", bom);
        }
        println!("Confidence: {:.0}%", enc.confidence * 100.0);
        println!("Valid UTF-8: {}", enc.valid_utf8);
        println!("Pure ASCII: {}", enc.pure_ascii);
        println!("Null bytes: {:.1}%", enc.null_percentage * 100.0);
    }
}

fn cmd_hexdump(file: &PathBuf, width: usize, annotated: bool, length: usize) {
    let data = match std::fs::read(file) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error reading {}: {}", file.display(), e);
            return;
        }
    };

    let data = if length > 0 && length < data.len() {
        &data[..length]
    } else {
        &data
    };

    println!("File: {} ({} bytes)", file.display(), data.len());
    println!();

    if annotated {
        print!("{}", hexdump::hexdump_annotated(data));
    } else {
        print!("{}", hexdump::hexdump(data, width));
    }
}

fn cmd_compare(file_a: &PathBuf, file_b: &PathBuf, json: bool) {
    let data_a = match std::fs::read(file_a) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error reading {}: {}", file_a.display(), e);
            return;
        }
    };

    let data_b = match std::fs::read(file_b) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error reading {}: {}", file_b.display(), e);
            return;
        }
    };

    let result = compare::compare(&data_a, &data_b);

    if json {
        let output = serde_json::json!({
            "file_a": file_a.display().to_string(),
            "file_b": file_b.display().to_string(),
            "similarity": result.similarity,
            "entropy_a": result.entropy_a,
            "entropy_b": result.entropy_b,
            "entropy_diff": result.entropy_diff,
            "size_a": result.size_a,
            "size_b": result.size_b,
            "frequency_similarity": result.frequency_similarity,
            "first_bytes_match": result.first_bytes_match,
            "summary": result.summary,
        });
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
    } else {
        println!("Comparing:");
        println!("  A: {} ({} bytes)", file_a.display(), result.size_a);
        println!("  B: {} ({} bytes)", file_b.display(), result.size_b);
        println!();
        println!("Similarity: {:.1}%", result.similarity * 100.0);
        println!(
            "Entropy A: {:.4} | Entropy B: {:.4}",
            result.entropy_a, result.entropy_b
        );
        println!("Entropy diff: {:.4}", result.entropy_diff);
        println!(
            "Frequency similarity: {:.1}%",
            result.frequency_similarity * 100.0
        );
        println!("First bytes match: {}", result.first_bytes_match);
        println!();
        println!("Summary: {}", result.summary);
    }
}

fn cmd_analyze(file: &PathBuf, json: bool) {
    let data = match std::fs::read(file) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error reading {}: {}", file.display(), e);
            return;
        }
    };

    let analysis = fileforge::analyze_bytes(&file.display().to_string(), &data);

    if json {
        let output = serde_json::json!({
            "path": analysis.path,
            "size": analysis.size,
            "detection": analysis.detection,
            "entropy": analysis.entropy,
            "entropy_class": analysis.entropy_class,
            "frequency": {
                "total": analysis.frequency.total,
                "unique_bytes": analysis.frequency.unique_bytes,
                "top_10": analysis.frequency.top_n(10).iter().map(|(b, c, r)| {
                    serde_json::json!({
                        "byte": format!("0x{:02x}", b),
                        "count": c,
                        "ratio": r,
                    })
                }).collect::<Vec<_>>(),
            },
            "classification": analysis.classification,
            "encoding": analysis.encoding,
            "encryption": analysis.encryption,
        });
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
    } else {
        println!("=== FileForge Analysis ===");
        println!();
        println!("File: {}", analysis.path);
        println!("Size: {} bytes", analysis.size);
        println!();

        // Type detection
        if let Some(d) = &analysis.detection {
            println!("Type: {} ({})", d.file_type, d.mime_type);
            if !d.extension.is_empty() {
                println!("Extension: .{}", d.extension);
            }
        } else {
            println!("Type: unknown");
        }
        println!();

        // Entropy
        println!(
            "Entropy: {:.4} / 8.0 ({})",
            analysis.entropy, analysis.entropy_class
        );
        println!(
            "Encrypted: {} | Compressed: {} | Structured: {}",
            analysis.encryption.likely_encrypted,
            analysis.encryption.likely_compressed,
            analysis.encryption.likely_structured
        );
        println!();

        // Byte frequency
        println!("Unique bytes: {} / 256", analysis.frequency.unique_bytes);
        println!(
            "Text: {} | Binary: {} | Unicode: {}",
            analysis.classification.likely_text,
            analysis.classification.likely_binary,
            analysis.classification.has_unicode
        );
        println!("Top 10 bytes:");
        for (byte, count, rel) in analysis.frequency.top_n(10) {
            let label = match byte {
                0x00 => "NUL".to_string(),
                0x09 => "TAB".to_string(),
                0x0a => "LF".to_string(),
                0x0d => "CR".to_string(),
                0x20 => "SPC".to_string(),
                b if b.is_ascii_graphic() => format!("'{}'", b as char),
                b => format!("0x{:02x}", b),
            };
            println!("  {:>4}: {:>8} ({:>5.1}%)", label, count, rel * 100.0);
        }
        println!();

        // Encoding
        println!("Encoding: {}", analysis.encoding.encoding);
        if let Some(bom) = &analysis.encoding.bom {
            println!("BOM: {}", bom);
        }
        println!(
            "UTF-8: {} | ASCII: {}",
            analysis.encoding.valid_utf8, analysis.encoding.pure_ascii
        );
    }
}

fn cmd_scan(dir: &Path, max_depth: usize, json: bool) {
    let mut file_types: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    let mut total = 0u64;
    let mut scanned = 0u64;

    fn scan_dir(
        dir: &std::path::Path,
        depth: usize,
        max_depth: usize,
        file_types: &mut std::collections::HashMap<String, Vec<String>>,
        total: &mut u64,
        scanned: &mut u64,
    ) {
        if depth > max_depth {
            return;
        }

        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return,
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                scan_dir(&path, depth + 1, max_depth, file_types, total, scanned);
            } else if path.is_file() {
                *total += 1;
                let data = match std::fs::read(&path) {
                    Ok(d) => d,
                    Err(_) => continue,
                };

                *scanned += 1;
                let detections = magic::detect_all(&data);
                let file_type = if detections.is_empty() {
                    "Unknown".to_string()
                } else {
                    detections[0].file_type.clone()
                };

                file_types
                    .entry(file_type)
                    .or_default()
                    .push(path.display().to_string());
            }
        }
    }

    scan_dir(dir, 0, max_depth, &mut file_types, &mut total, &mut scanned);

    if json {
        let output: Vec<_> = file_types
            .iter()
            .map(|(ft, files)| {
                serde_json::json!({
                    "type": ft,
                    "count": files.len(),
                    "files": files,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "directory": dir.display().to_string(),
                "max_depth": max_depth,
                "total_files": total,
                "scanned": scanned,
                "types": output,
            }))
            .unwrap()
        );
    } else {
        println!("Scan results for: {}", dir.display());
        println!("Max depth: {}", max_depth);
        println!("Total files: {}", total);
        println!("Scanned: {}", scanned);
        println!();

        let mut sorted: Vec<_> = file_types.into_iter().collect();
        sorted.sort_by_key(|b| std::cmp::Reverse(b.1.len()));

        for (file_type, files) in &sorted {
            println!("{}: {} files", file_type, files.len());
        }
    }
}

fn cmd_info() {
    println!("FileForge Magic Byte Database");
    println!("==============================");
    println!();
    println!("Total signatures: {}", magic::signature_count());
    println!();
    println!("Supported categories:");
    println!("  Images:     PNG, JPEG, GIF, BMP, ICO, TIFF, WebP, SVG, HEIF, AVIF");
    println!("  Archives:   ZIP, RAR, 7z, GZIP, BZIP2, XZ, LZMA, TAR, ZSTD");
    println!("  Documents:  PDF, DOC (OLE2)");
    println!("  Executables: ELF, PE, Mach-O, WASM, Java Class");
    println!("  Audio:      MP3, FLAC, OGG, WAV, MIDI, AU");
    println!("  Video:      MP4, AVI, MKV, WebM, FLV, MOV");
    println!("  Data:       SQLite, BSON, MessagePack, CBOR");
    println!("  Security:   PGP keys, SSH keys, PEM certificates");
    println!("  Scripts:    Python, Bash, Perl, Ruby, Node.js, PHP");
    println!("  Web:        HTML, XML, JSON, SVG");
    println!("  Git:        pack, bundle, index");
    println!("  Fonts:      TTF, OTF, WOFF, WOFF2, DFONT");
    println!("  Network:    PCAP, BitTorrent");
    println!("  Disk:       ISO 9660, DMG, CramFS, SquashFS, ext2/3/4, NTFS");
    println!("  Misc:       DS_Store, DEX, Python bytecode, Java serialization");
    println!();
    println!("Analysis modules:");
    println!("  entropy    Shannon entropy, encryption/compression detection");
    println!("  frequency  Byte frequency histogram, text/binary classification");
    println!("  encoding   UTF-8/16/32, ASCII, Latin-1 detection via BOM + heuristics");
    println!("  hexdump    Standard, annotated, compact, and comparison hex dumps");
    println!("  compare    Cosine similarity, entropy comparison, file fingerprinting");
}
