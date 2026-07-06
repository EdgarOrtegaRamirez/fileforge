/// File comparison by entropy profile and byte frequency.
///
/// Compares two files to determine similarity, detect if one is encrypted
/// while the other is not, and identify structural differences.
use crate::entropy;
use crate::frequency::ByteFrequency;

/// Result of comparing two files.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ComparisonResult {
    /// Overall similarity score (0.0 = completely different, 1.0 = identical).
    pub similarity: f64,
    /// Entropy of first file.
    pub entropy_a: f64,
    /// Entropy of second file.
    pub entropy_b: f64,
    /// Entropy difference.
    pub entropy_diff: f64,
    /// Size of first file.
    pub size_a: usize,
    /// Size of second file.
    pub size_b: usize,
    /// Size ratio (smaller/larger).
    pub size_ratio: f64,
    /// Byte frequency cosine similarity.
    pub frequency_similarity: f64,
    /// First byte comparison.
    pub first_bytes_match: bool,
    /// Summary description.
    pub summary: String,
}

/// Compare two byte slices by their statistical properties.
pub fn compare(data_a: &[u8], data_b: &[u8]) -> ComparisonResult {
    let entropy_a = entropy::shannon_entropy(data_a);
    let entropy_b = entropy::shannon_entropy(data_b);
    let entropy_diff = (entropy_a - entropy_b).abs();

    let freq_a = ByteFrequency::from_bytes(data_a);
    let freq_b = ByteFrequency::from_bytes(data_b);

    let frequency_similarity = cosine_similarity(&freq_a.counts, &freq_b.counts);

    // Size ratio
    let size_a = data_a.len();
    let size_b = data_b.len();
    let size_ratio = if size_a.max(size_b) > 0 {
        size_a.min(size_b) as f64 / size_a.max(size_b) as f64
    } else {
        1.0
    };

    // First bytes match
    let first_bytes_match = !data_a.is_empty()
        && !data_b.is_empty()
        && data_a[0] == data_b[0]
        && data_a.len().min(data_b.len()) >= 4
        && data_a[..4] == data_b[..4];

    // Overall similarity combines entropy, frequency, and size
    let similarity =
        (frequency_similarity * 0.5 + (1.0 - entropy_diff / 8.0) * 0.3 + size_ratio * 0.2)
            .clamp(0.0, 1.0);

    // Generate summary
    let summary = generate_summary(
        similarity,
        entropy_a,
        entropy_b,
        entropy_diff,
        size_a,
        size_b,
        first_bytes_match,
        frequency_similarity,
    );

    ComparisonResult {
        similarity,
        entropy_a,
        entropy_b,
        entropy_diff,
        size_a,
        size_b,
        size_ratio,
        frequency_similarity,
        first_bytes_match,
        summary,
    }
}

/// Cosine similarity between two frequency vectors.
fn cosine_similarity(a: &[u64], b: &[u64]) -> f64 {
    if a.len() != b.len() {
        return 0.0;
    }
    if a.is_empty() {
        return 1.0;
    }

    let mut dot_product = 0.0;
    let mut norm_a = 0.0;
    let mut norm_b = 0.0;

    for (ai, bi) in a.iter().zip(b.iter()) {
        let af = *ai as f64;
        let bf = *bi as f64;
        dot_product += af * bf;
        norm_a += af * af;
        norm_b += bf * bf;
    }

    let denominator = norm_a.sqrt() * norm_b.sqrt();
    if denominator == 0.0 {
        // Both vectors are zero — they are identical
        1.0
    } else {
        dot_product / denominator
    }
}

fn generate_summary(
    similarity: f64,
    entropy_a: f64,
    entropy_b: f64,
    entropy_diff: f64,
    size_a: usize,
    size_b: usize,
    first_bytes_match: bool,
    _freq_sim: f64,
) -> String {
    let mut parts = Vec::new();

    if similarity > 0.95 {
        parts.push("Files are nearly identical".to_string());
    } else if similarity > 0.8 {
        parts.push("Files are very similar".to_string());
    } else if similarity > 0.5 {
        parts.push("Files share some characteristics".to_string());
    } else {
        parts.push("Files are quite different".to_string());
    }

    if first_bytes_match {
        parts.push("same file header".to_string());
    }

    if entropy_diff > 2.0 {
        if entropy_a > entropy_b {
            parts.push(format!(
                "File A is significantly more random (entropy {:.1} vs {:.1})",
                entropy_a, entropy_b
            ));
        } else {
            parts.push(format!(
                "File B is significantly more random (entropy {:.1} vs {:.1})",
                entropy_b, entropy_a
            ));
        }
    }

    if (size_a as f64 / size_b as f64).abs() > 2.0 || (size_b as f64 / size_a as f64).abs() > 2.0 {
        parts.push(format!(
            "Size differs significantly ({} vs {} bytes)",
            size_a, size_b
        ));
    }

    parts.join(". ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compare_identical() {
        let data = b"Hello, World!";
        let result = compare(data, data);
        assert!(result.similarity > 0.9);
    }

    #[test]
    fn test_compare_different() {
        let a = b"Hello, World!";
        let b = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        let result = compare(a, b);
        assert!(result.similarity < 0.8);
    }

    #[test]
    fn test_compare_empty() {
        let result = compare(b"", b"");
        assert_eq!(result.similarity, 1.0);
    }

    #[test]
    fn test_cosine_similarity_identical() {
        let data = [1u64; 256];
        assert!((cosine_similarity(&data, &data) - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_cosine_similarity_orthogonal() {
        let a = [1u64; 256];
        let mut b = [0u64; 256];
        b[0] = 1;
        // Not exactly 0 because all a's are 1
        let sim = cosine_similarity(&a, &b);
        assert!(sim < 0.5);
    }

    #[test]
    fn test_summary_generation() {
        let data = b"Test data for comparison";
        let result = compare(data, data);
        assert!(!result.summary.is_empty());
    }
}
