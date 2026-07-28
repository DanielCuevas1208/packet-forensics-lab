//! Entropy and label-metric helpers used by the analyzers.

/// Shannon entropy in bits per symbol of a byte slice.
/// Returns zero for empty inputs.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let total = data.len() as f64;
    let mut sum = 0.0;
    for &c in counts.iter() {
        if c == 0 {
            continue;
        }
        let p = c as f64 / total;
        sum -= p * p.log2();
    }
    sum
}

/// Split a domain name into its labels. Empty labels are removed.
pub fn labels(name: &str) -> Vec<&str> {
    name.split('.').filter(|s| !s.is_empty()).collect()
}

/// The registered-domain approximation: the last two labels joined by a dot.
/// For names with fewer labels, the entire name is returned.
pub fn registered_domain(name: &str) -> String {
    let labels = labels(name);
    if labels.len() <= 2 {
        return name.to_lowercase();
    }
    let n = labels.len();
    format!("{}.{}", labels[n - 2], labels[n - 1])
}

/// A single labelclassed as a tunneling candidate because it is long and noisy.
pub fn label_is_noisy(label: &str) -> bool {
    let bytes = label.as_bytes();
    if bytes.len() < 12 {
        return false;
    }
    shannon_entropy(bytes) >= 3.5
}
