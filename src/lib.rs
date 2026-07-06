/// FileForge: Universal Binary Analysis Toolkit
///
/// A comprehensive toolkit for analyzing binary files using information theory,
/// statistical analysis, and structural parsing. Detects file types by magic bytes,
/// computes Shannon entropy, analyzes byte frequencies, identifies encodings,
/// and generates hex dumps.
pub mod compare;
pub mod encoding;
pub mod entropy;
pub mod frequency;
pub mod hexdump;
pub mod magic;

/// Unified file analysis result combining all analysis modules.
#[derive(Debug, Clone, serde::Serialize)]
pub struct FileAnalysis {
    /// File path analyzed.
    pub path: String,
    /// File size in bytes.
    pub size: usize,
    /// Magic byte detection result.
    pub detection: Option<magic::FileDetection>,
    /// Shannon entropy (0.0-8.0).
    pub entropy: f64,
    /// Entropy classification.
    pub entropy_class: &'static str,
    /// Byte frequency analysis.
    pub frequency: frequency::ByteFrequency,
    /// Byte classification (text/binary/etc).
    pub classification: frequency::ByteClassification,
    /// Encoding detection.
    pub encoding: encoding::EncodingDetection,
    /// Encryption/compression detection.
    pub encryption: entropy::EncryptionDetection,
}

/// Analyze a file by reading its contents and running all analyses.
pub fn analyze_file(path: &str) -> Result<FileAnalysis, std::io::Error> {
    let data = std::fs::read(path)?;
    Ok(analyze_bytes(path, &data))
}

/// Analyze raw bytes with all analysis modules.
pub fn analyze_bytes(path: &str, data: &[u8]) -> FileAnalysis {
    let detection = magic::detect(data);
    let ent = entropy::shannon_entropy(data);
    let ent_class = entropy::entropy_class(ent);
    let freq = frequency::ByteFrequency::from_bytes(data);
    let classification = freq.classify();
    let enc = encoding::detect_encoding(data);
    let encrypt = entropy::detect_encryption(data);

    FileAnalysis {
        path: path.to_string(),
        size: data.len(),
        detection,
        entropy: ent,
        entropy_class: ent_class,
        frequency: freq,
        classification,
        encoding: enc,
        encryption: encrypt,
    }
}
