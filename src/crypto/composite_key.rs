use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

use crate::crypto::hash::sha256;
use crate::crypto::keyfile::KeyFile;

/// Composite key assembled from multiple components, wiped when dropped.
#[derive(Clone, Default)]
pub struct CompositeKey {
    parts: Vec<Zeroizing<Vec<u8>>>,
}

impl std::fmt::Debug for CompositeKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompositeKey")
            .field("parts", &self.parts.len())
            .finish_non_exhaustive()
    }
}

impl CompositeKey {
    /// Create an empty composite key.
    pub fn new() -> Self {
        Self::default()
    }

    /// Return true if no components are present.
    pub fn is_empty(&self) -> bool {
        self.parts.is_empty()
    }

    /// Add a password component.
    pub fn add_password(&mut self, password: &SecretString) {
        let hash = sha256(password.expose_secret().as_bytes());
        self.parts.push(Zeroizing::new(hash.to_vec()));
    }

    /// Add a key file component.
    pub fn add_keyfile(&mut self, key_file: &KeyFile) {
        self.parts.push(Zeroizing::new(key_file.raw_key().to_vec()));
    }

    /// Add a precomputed component.
    pub fn add_component(&mut self, component: Vec<u8>) {
        self.parts.push(Zeroizing::new(component));
    }

    /// Compute the raw composite key (SHA-256 of concatenated components).
    pub fn raw_key(&self) -> Zeroizing<Vec<u8>> {
        let total_len: usize = self.parts.iter().map(|part| part.len()).sum();
        let mut buffer = Zeroizing::new(Vec::with_capacity(total_len));
        for part in &self.parts {
            buffer.extend_from_slice(part);
        }
        Zeroizing::new(sha256(&buffer).to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn composite_key_hashes_components() {
        let mut key = CompositeKey::new();
        key.add_component(vec![1, 2, 3]);
        let raw = key.raw_key();
        assert_eq!(raw.len(), 32);
    }

    #[test]
    fn composite_key_empty() {
        let key = CompositeKey::new();
        assert!(key.is_empty());
    }
}
