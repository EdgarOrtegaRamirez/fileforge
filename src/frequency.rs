/// Byte frequency analysis.
///
/// Computes histograms of byte value distributions, identifies dominant
/// byte values, and provides statistical summaries.

/// Byte frequency histogram (256 buckets for each byte value 0-255).
#[derive(Debug, Clone)]
pub struct ByteFrequency {
    /// Count of each byte value (0-255).
    pub counts: [u64; 256],
    /// Total number of bytes analyzed.
    pub total: u64,
    /// Number of distinct byte values present.
    pub unique_bytes: usize,
}

impl serde::Serialize for ByteFrequency {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("ByteFrequency", 3)?;
        state.serialize_field("counts", &self.counts.to_vec())?;
        state.serialize_field("total", &self.total)?;
        state.serialize_field("unique_bytes", &self.unique_bytes)?;
        state.end()
    }
}

impl ByteFrequency {
    /// Compute frequency histogram for a byte slice.
    pub fn from_bytes(data: &[u8]) -> Self {
        let mut counts = [0u64; 256];
        for &byte in data {
            counts[byte as usize] += 1;
        }
        let unique_bytes = counts.iter().filter(|&&c| c > 0).count();
        ByteFrequency {
            counts,
            total: data.len() as u64,
            unique_bytes,
        }
    }

    /// Get the relative frequency of a byte value.
    pub fn relative_freq(&self, byte: u8) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            self.counts[byte as usize] as f64 / self.total as f64
        }
    }

    /// Get the N most frequent byte values.
    pub fn top_n(&self, n: usize) -> Vec<(u8, u64, f64)> {
        let mut pairs: Vec<(u8, u64)> = self
            .counts
            .iter()
            .enumerate()
            .map(|(i, &c)| (i as u8, c))
            .filter(|(_, c)| *c > 0)
            .collect();
        pairs.sort_by(|a, b| b.1.cmp(&a.1));
        pairs
            .into_iter()
            .take(n)
            .map(|(b, c)| (b, c, self.relative_freq(b)))
            .collect()
    }

    /// Classify the byte distribution into categories.
    pub fn classify(&self) -> ByteClassification {
        let printable = (0x20..=0x7e).map(|i| self.counts[i]).sum::<u64>();
        let null = self.counts[0];
        let control = (0x01..0x20).map(|i| self.counts[i]).sum::<u64>()
            - self.counts[0x0a]
            - self.counts[0x0d];
        let newline = self.counts[0x0a];
        let cr = self.counts[0x0d];
        let tab = self.counts[0x09];
        let high_bit = (0x80..=0xff).map(|i| self.counts[i]).sum::<u64>();
        let whitespace = newline + cr + tab + self.counts[0x20];

        let total = self.total as f64;
        let print_ratio = if total > 0.0 {
            printable as f64 / total
        } else {
            0.0
        };
        let null_ratio = if total > 0.0 {
            null as f64 / total
        } else {
            0.0
        };
        let high_ratio = if total > 0.0 {
            high_bit as f64 / total
        } else {
            0.0
        };

        let likely_text = print_ratio > 0.7 && null_ratio < 0.01;
        let likely_binary = print_ratio < 0.5 || null_ratio > 0.05;
        let has_unicode = high_bit > 0 && !likely_binary;

        ByteClassification {
            printable,
            null,
            control,
            newline,
            carriage_return: cr,
            tab,
            high_bit,
            whitespace,
            print_ratio,
            null_ratio,
            high_bit_ratio: high_ratio,
            likely_text,
            likely_binary,
            has_unicode,
        }
    }
}

/// Statistical classification of byte distribution.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ByteClassification {
    pub printable: u64,
    pub null: u64,
    pub control: u64,
    pub newline: u64,
    pub carriage_return: u64,
    pub tab: u64,
    pub high_bit: u64,
    pub whitespace: u64,
    pub print_ratio: f64,
    pub null_ratio: f64,
    pub high_bit_ratio: f64,
    pub likely_text: bool,
    pub likely_binary: bool,
    pub has_unicode: bool,
}

/// Format a frequency table as a text histogram.
pub fn format_histogram(freq: &ByteFrequency, max_bar_width: usize) -> String {
    let top = freq.top_n(32);
    if top.is_empty() {
        return String::from("(empty data)");
    }

    let max_count = top.iter().map(|(_, c, _)| *c).max().unwrap_or(1);
    let mut output = String::new();

    for (byte, count, rel) in &top {
        let bar_len = if max_count > 0 {
            (*count as usize * max_bar_width) / max_count as usize
        } else {
            0
        };
        let label = match *byte {
            0x00 => "NUL".to_string(),
            0x09 => "TAB".to_string(),
            0x0a => " LF ".to_string(),
            0x0d => " CR ".to_string(),
            0x20 => "SPC".to_string(),
            b if b.is_ascii_graphic() || b == b' ' => format!(" '{}'", *byte as char),
            b => format!("0x{:02x}", b),
        };
        output.push_str(&format!(
            " {:>4} │ {:>8} ({:>5.1}%) │{}\n",
            label,
            count,
            rel * 100.0,
            "█".repeat(bar_len)
        ));
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frequency_empty() {
        let freq = ByteFrequency::from_bytes(b"");
        assert_eq!(freq.total, 0);
        assert_eq!(freq.unique_bytes, 0);
    }

    #[test]
    fn test_frequency_uniform() {
        let data = vec![0u8; 100];
        let freq = ByteFrequency::from_bytes(&data);
        assert_eq!(freq.total, 100);
        assert_eq!(freq.unique_bytes, 1);
        assert_eq!(freq.counts[0], 100);
        assert!((freq.relative_freq(0) - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_frequency_text() {
        let freq = ByteFrequency::from_bytes(b"Hello, World!");
        assert_eq!(freq.total, 13);
        assert!(freq.unique_bytes > 5);
        assert!(freq.relative_freq(b'H') > 0.0);
    }

    #[test]
    fn test_top_n() {
        let freq = ByteFrequency::from_bytes(b"aaabbbccc");
        let top = freq.top_n(3);
        assert_eq!(top.len(), 3);
        // 'a', 'b', 'c' each appear 3 times
        assert_eq!(top[0].1, 3);
    }

    #[test]
    fn test_classify_text() {
        let freq = ByteFrequency::from_bytes(b"Hello, this is a text file.\n");
        let class = freq.classify();
        assert!(class.likely_text);
        assert!(!class.likely_binary);
        assert!(class.newline > 0);
    }

    #[test]
    fn test_classify_binary() {
        let data: Vec<u8> = (0..=255).collect();
        let freq = ByteFrequency::from_bytes(&data);
        let class = freq.classify();
        assert!(class.likely_binary);
    }

    #[test]
    fn test_format_histogram() {
        let freq = ByteFrequency::from_bytes(b"aaabbbccc");
        let hist = format_histogram(&freq, 40);
        assert!(hist.contains("a"));
        assert!(hist.contains("b"));
    }
}
