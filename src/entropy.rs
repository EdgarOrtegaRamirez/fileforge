/// Shannon entropy calculation and analysis.
///
/// Computes information entropy using Shannon's formula:
/// H(X) = -Σ p(x) * log2(p(x))
///
/// Supports global entropy, windowed entropy scanning, and entropy profiling.
/// Compute Shannon entropy of a byte slice.
///
/// Returns a value between 0.0 (all bytes identical) and 8.0 (perfectly random).
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut freq = [0u64; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Compute entropy for each byte value (0-255).
///
/// Returns an array of 256 entropy contributions.
pub fn byte_entropy_contributions(data: &[u8]) -> [f64; 256] {
    let mut contributions = [0.0f64; 256];
    if data.is_empty() {
        return contributions;
    }

    let mut freq = [0u64; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }

    let len = data.len() as f64;

    for i in 0..256 {
        if freq[i] > 0 {
            let p = freq[i] as f64 / len;
            contributions[i] = -p * p.log2();
        }
    }

    contributions
}

/// Compute windowed entropy using a sliding window.
///
/// Returns a vector of (offset, entropy) pairs for each window position.
pub fn windowed_entropy(data: &[u8], window_size: usize) -> Vec<(usize, f64)> {
    if data.is_empty() || window_size == 0 || window_size > data.len() {
        return vec![];
    }

    let mut results = Vec::with_capacity(data.len() - window_size + 1);
    let mut freq = [0u64; 256];

    // Initialize first window
    for i in 0..window_size {
        freq[data[i] as usize] += 1;
    }
    results.push((0, compute_entropy_from_freq(&freq, window_size)));

    // Slide the window
    for i in 1..=data.len() - window_size {
        freq[data[i - 1] as usize] -= 1;
        freq[data[i + window_size - 1] as usize] += 1;
        results.push((i, compute_entropy_from_freq(&freq, window_size)));
    }

    results
}

fn compute_entropy_from_freq(freq: &[u64; 256], total: usize) -> f64 {
    let len = total as f64;
    let mut entropy = 0.0;

    for &count in freq.iter() {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Classify entropy level into a human-readable category.
pub fn entropy_class(entropy: f64) -> &'static str {
    match entropy {
        0.0..=1.0 => "Very Low (highly structured)",
        1.0..=3.0 => "Low (text, simple data)",
        3.0..=5.0 => "Medium (mixed content)",
        5.0..=6.5 => "High (compressed/encoded)",
        6.5..=7.5 => "Very High (near random)",
        7.5..=8.0 => "Maximum (perfectly random)",
        _ => "Unknown",
    }
}

/// Detect if data appears to be encrypted or compressed.
///
/// Uses entropy threshold and byte distribution analysis.
pub fn detect_encryption(data: &[u8]) -> EncryptionDetection {
    let entropy = shannon_entropy(data);
    let contributions = byte_entropy_contributions(data);

    // Count active bytes (non-zero entropy contribution)
    let active_bytes: usize = contributions.iter().filter(|&&x| x > 0.0).count();

    // Compute chi-squared statistic for uniformity
    let chi_squared = compute_chi_squared(data);

    // Shannon entropy threshold for encrypted data
    let likely_encrypted = entropy > 7.5 && active_bytes > 200;

    // Compressed data typically has entropy between 5.0 and 7.5
    let likely_compressed = (5.0..=7.5).contains(&entropy);

    // Low entropy with few active bytes = structured data
    let likely_structured = entropy < 3.0 && active_bytes < 50;

    EncryptionDetection {
        entropy,
        chi_squared,
        active_bytes,
        likely_encrypted,
        likely_compressed,
        likely_structured,
    }
}

/// Chi-squared statistic for byte distribution uniformity.
fn compute_chi_squared(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut freq = [0u64; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }

    let expected = data.len() as f64 / 256.0;
    let mut chi_sq = 0.0;

    for &count in &freq {
        let diff = count as f64 - expected;
        chi_sq += diff * diff / expected;
    }

    chi_sq
}

/// Result of encryption/compression detection.
#[derive(Debug, Clone, serde::Serialize)]
pub struct EncryptionDetection {
    pub entropy: f64,
    pub chi_squared: f64,
    pub active_bytes: usize,
    pub likely_encrypted: bool,
    pub likely_compressed: bool,
    pub likely_structured: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_empty() {
        assert_eq!(shannon_entropy(b""), 0.0);
    }

    #[test]
    fn test_entropy_uniform() {
        // All same byte = 0 entropy
        assert_eq!(shannon_entropy(b"aaaaaaaa"), 0.0);
    }

    #[test]
    fn test_entropy_max() {
        // Perfect alternating = 1 bit entropy
        let data: Vec<u8> = (0..256).map(|i| (i % 2) as u8).collect();
        let e = shannon_entropy(&data);
        assert!((e - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_entropy_text() {
        let text = b"The quick brown fox jumps over the lazy dog";
        let e = shannon_entropy(text);
        assert!(e > 3.0 && e < 5.0);
    }

    #[test]
    fn test_entropy_binary() {
        // Random-ish binary data
        let data: Vec<u8> = (0..=255).collect();
        let e = shannon_entropy(&data);
        assert!(e > 7.5);
    }

    #[test]
    fn test_windowed_entropy() {
        let data = b"aaaaaaaaaaaaaabbbbbbbbbbbbbb";
        let results = windowed_entropy(data, 8);
        assert!(!results.is_empty());
        // First window (all 'a's) should have 0 entropy
        assert_eq!(results[0].1, 0.0);
    }

    #[test]
    fn test_entropy_class() {
        assert_eq!(entropy_class(0.0), "Very Low (highly structured)");
        assert_eq!(entropy_class(4.0), "Medium (mixed content)");
        assert_eq!(entropy_class(7.8), "Maximum (perfectly random)");
    }

    #[test]
    fn test_detect_encryption() {
        let random_data: Vec<u8> = (0..1000).map(|i| ((i * 7 + 13) % 256) as u8).collect();
        let detection = detect_encryption(&random_data);
        assert!(detection.entropy > 5.0);
    }

    #[test]
    fn test_chi_squared() {
        let data = vec![0u8; 1000];
        let chi = compute_chi_squared(&data);
        // All zeros = very high chi-squared (all in one bin)
        assert!(chi > 1000.0);
    }
}
