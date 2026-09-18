//! The key store: API keys hashed at rest, each with its id and its expiry.
//!
//! What is kept for a key is its id — the name an operator and the record
//! know it by — the SHA-256 of the key, and the moment it stops being good,
//! in seconds since the Unix epoch. The key is not kept.
//!
//! The first gate names a key on the record in one of two forms, and the
//! store finds a key by either: the public id the issuer put in front of
//! the secret, or `sha256:` and the first eight bytes of the key's SHA-256
//! in hexadecimal. A name is only where to look. The key itself is then
//! hashed and compared with every key the name found, each in constant time
//! and with no early exit.

use authenticate::store::{KEY_LENGTH, constant_time_eq, hex, sha256};

/// What a name that is a digest of the key starts with.
pub const DIGEST_PREFIX: &str = "sha256:";
/// How many bytes of the key's SHA-256 the digest form carries.
pub const DIGEST_BYTES: usize = 8;

/// One key as the store holds it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Key {
    id: String,
    hash: [u8; KEY_LENGTH],
    expiry: Option<i64>,
}

impl Key {
    /// The name the key is known by; never the key.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// SHA-256 of the key.
    #[must_use]
    pub const fn hash(&self) -> &[u8; KEY_LENGTH] {
        &self.hash
    }

    /// The first second, since the Unix epoch, at which the key is no longer
    /// good. `None` is a key that does not expire.
    #[must_use]
    pub const fn expiry(&self) -> Option<i64> {
        self.expiry
    }

    /// The digest form of this key's name: `sha256:` and sixteen hexadecimal
    /// digits, as the first gate writes it for a key with no id in it.
    #[must_use]
    pub fn digest(&self) -> String {
        format!("{DIGEST_PREFIX}{}", hex(&self.hash[..DIGEST_BYTES]))
    }

    /// Whether `name` is this key's, in either form.
    #[must_use]
    pub fn is_named(&self, name: &str) -> bool {
        name == self.id || name == self.digest()
    }
}

/// The keys a node takes, built from configuration and read-only after.
#[derive(Clone, Debug, Default)]
pub struct KeyStore {
    keys: Vec<Key>,
}

impl KeyStore {
    /// A store holding nothing, which verifies nobody.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Hold `key` under `id`, hashed. The key is not kept. A second key
    /// under the same id stands beside the first, which is how a key is
    /// rotated without a gap.
    pub fn insert(&mut self, id: &str, key: &str, expiry: Option<i64>) {
        self.insert_hash(id, sha256(key.as_bytes()), expiry);
    }

    /// Hold a key hashed elsewhere, as configuration carries it.
    pub fn insert_hash(&mut self, id: &str, hash: [u8; KEY_LENGTH], expiry: Option<i64>) {
        self.keys.push(Key {
            id: id.to_string(),
            hash,
            expiry,
        });
    }

    /// How many keys are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether nothing is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// The keys `name` names, by id or by digest. Finding one proves
    /// nothing: a name is public.
    pub fn named<'a>(&'a self, name: &str) -> impl Iterator<Item = &'a Key> + use<'a> {
        let name = name.to_string();
        self.keys.iter().filter(move |key| key.is_named(&name))
    }

    /// The key `name` names whose hash is `hash`, compared in constant time
    /// against every key the name found.
    #[must_use]
    pub fn holding(&self, name: &str, hash: &[u8; KEY_LENGTH]) -> Option<&Key> {
        self.named(name).fold(None, |found, key| {
            if constant_time_eq(&key.hash, hash) {
                found.or(Some(key))
            } else {
                found
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_is_found_by_its_id_or_its_digest_and_the_key_itself_is_not_kept() {
        let mut store = KeyStore::new();
        store.insert("pk_7f3a", "pk_7f3a.c2VjcmV0", Some(42));
        let hash = sha256(b"pk_7f3a.c2VjcmV0");
        let held = store.holding("pk_7f3a", &hash).expect("held");
        assert_eq!(held.id(), "pk_7f3a");
        assert_eq!(held.expiry(), Some(42));
        assert_eq!(held.hash(), &hash);
        assert_eq!(held.digest(), format!("sha256:{}", &hex(&hash)[..16]));
        assert!(store.holding(&held.digest(), &hash).is_some());
        assert!(!format!("{store:?}").contains("c2VjcmV0"));
    }

    #[test]
    fn the_digest_is_the_first_eight_bytes_of_the_keys_sha_256() {
        // SHA-256("abc") = ba7816bf 8f01cfea …, FIPS 180-2 appendix B.1: the
        // same name the first gate gives the key.
        let mut store = KeyStore::new();
        store.insert("abc-key", "abc", None);
        let held = store.named("sha256:ba7816bf8f01cfea").next().expect("held");
        assert_eq!(held.id(), "abc-key");
    }

    #[test]
    fn a_name_alone_holds_nothing_and_neither_does_a_key_under_another_name() {
        let mut store = KeyStore::new();
        store.insert("partner-x", "key-x", None);
        store.insert("partner-y", "key-y", None);
        assert_eq!(store.named("partner-x").count(), 1);
        assert!(store.holding("partner-x", &sha256(b"guess")).is_none());
        assert!(store.holding("partner-y", &sha256(b"key-x")).is_none());
        assert!(store.holding("nobody", &sha256(b"key-x")).is_none());
    }

    #[test]
    fn a_rotated_key_stands_beside_the_one_it_replaces() {
        let mut store = KeyStore::new();
        assert!(store.is_empty());
        store.insert("partner-x", "old", Some(100));
        store.insert_hash("partner-x", sha256(b"new"), None);
        assert_eq!(store.len(), 2);
        assert_eq!(store.named("partner-x").count(), 2);
        let expiry = |key: &[u8]| store.holding("partner-x", &sha256(key)).map(Key::expiry);
        assert_eq!(expiry(b"old"), Some(Some(100)));
        assert_eq!(expiry(b"new"), Some(None));
    }
}
