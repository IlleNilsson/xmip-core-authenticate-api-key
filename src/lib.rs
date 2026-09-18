#![forbid(unsafe_code)]

//! Authenticate by API key: a key against a key store, with its expiry.
//!
//! No standard stands behind an API key; the convention is universal. The
//! first gate reads the key out of a header or a query parameter and puts a
//! name for it on the claim — the public id in front of the secret where
//! the issuer's keys carry one, else `sha256:` and the first eight bytes of
//! the key's SHA-256 — while the key itself rides on `Presented::proof`
//! under `api-key` and never reaches the record. This gate finds the keys
//! the name names, by either form, hashes the key that was presented,
//! compares it with each of them in constant time, and then reads the
//! expiry. The name is only where to look: nothing is proven by it.
//!
//! The store is hashed at rest: what the node keeps is SHA-256 of the key,
//! which is enough for a secret the node minted with full entropy and would
//! not be for a password. An expired key is refused saying so, with the
//! moment it expired; a key the name does not hold is refused without
//! saying what the store holds.

pub mod store;

pub use store::{DIGEST_PREFIX, Key, KeyStore};

use authenticate::store::sha256;
use authenticate::{AuthenticateError, Authenticator, Presented};
use context::Verified;
use std::time::{SystemTime, UNIX_EPOCH};
use xcore::{Mechanism, mechanism};

/// The proof name this verifier reads off a `Presented`: the key itself.
pub const PROOF: &str = "api-key";

/// The evidence name the first gate says where the key was found under:
/// `header:<name>` or `query:<name>`. Not read here; it reaches the record.
pub const SOURCE: &str = "api-key.source";

type Clock = Box<dyn Fn() -> i64 + Send + Sync>;

/// Seconds since the Unix epoch, now.
#[must_use]
pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            i64::try_from(since.as_secs()).unwrap_or(i64::MAX)
        })
}

/// Verifies an `api-key` claim with an `api-key` proof against a key store.
pub struct ApiKeyAuthenticator {
    store: KeyStore,
    clock: Clock,
}

impl ApiKeyAuthenticator {
    #[must_use]
    pub fn new(store: KeyStore) -> Self {
        Self {
            store,
            clock: Box::new(now),
        }
    }

    /// Where the time comes from; the tests pin it.
    #[must_use]
    pub fn with_clock(mut self, clock: impl Fn() -> i64 + Send + Sync + 'static) -> Self {
        self.clock = Box::new(clock);
        self
    }

    /// The keys this verifies against.
    #[must_use]
    pub fn store(&self) -> &KeyStore {
        &self.store
    }
}

impl Authenticator for ApiKeyAuthenticator {
    fn mechanism(&self) -> Mechanism {
        mechanism::api_key()
    }

    fn verify(&self, presented: &Presented) -> Result<Verified, AuthenticateError> {
        let name = presented.mechanism.name();
        if name != self.mechanism().name() {
            return Err(AuthenticateError::new(format!(
                "'{name}' was presented and this authenticator verifies api-key"
            )));
        }
        let secret = presented.proof(PROOF).ok_or_else(|| {
            AuthenticateError::new(format!(
                "no '{PROOF}' proof was presented with the key '{}'",
                presented.value
            ))
        })?;
        if secret.is_empty() {
            return Err(AuthenticateError::new("the key presented is empty"));
        }
        let hash = sha256(secret.as_bytes());
        let Some(key) = self.store.holding(&presented.value, &hash) else {
            return Ok(Verified::Refused);
        };
        let now = (self.clock)();
        if let Some(expiry) = key.expiry()
            && now >= expiry
        {
            return Err(AuthenticateError::new(format!(
                "the key '{}' expired at {expiry} and it is {now}",
                key.id()
            )));
        }
        Ok(Verified::Proven)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use authenticate::{Acceptance, PartyRegistry, Refusal, authenticate};
    use xcore::{PartyId, Purpose};

    const NOW: i64 = 1_800_000_000;

    fn verifier() -> ApiKeyAuthenticator {
        let mut store = KeyStore::new();
        store.insert("partner-x", "k-7f3a9c2e51d84b60", None);
        store.insert("partner-y", "k-0badc0de0badc0de", Some(NOW + 60));
        store.insert("partner-z", "k-expired-yesterday", Some(NOW - 86_400));
        ApiKeyAuthenticator::new(store).with_clock(|| NOW)
    }

    fn digest_of_partner_x(verifier: &ApiKeyAuthenticator) -> String {
        let mut named = verifier.store().named("partner-x");
        named.next().expect("held").digest()
    }

    fn claim(id: &str, key: &str) -> Presented {
        Presented::passed(mechanism::api_key(), id).with_proof(PROOF, key)
    }

    #[test]
    fn a_key_the_store_holds_proves_the_claim_that_names_it() {
        let verifier = verifier();
        assert_eq!(
            verifier
                .verify(&claim("partner-x", "k-7f3a9c2e51d84b60"))
                .expect("verified"),
            Verified::Proven
        );
        // Not yet expired is still good.
        assert_eq!(
            verifier
                .verify(&claim("partner-y", "k-0badc0de0badc0de"))
                .expect("verified"),
            Verified::Proven
        );
        // A key with no id in it is named by its digest, as the first gate
        // writes it, with where it was found as evidence.
        let digest = digest_of_partner_x(&verifier);
        assert!(digest.starts_with(DIGEST_PREFIX) && digest.len() == 23);
        let by_digest =
            claim(&digest, "k-7f3a9c2e51d84b60").with_evidence(SOURCE, "header:x-api-key");
        assert_eq!(
            verifier.verify(&by_digest).expect("verified"),
            Verified::Proven
        );
    }

    #[test]
    fn a_key_the_store_does_not_hold_is_refused() {
        assert_eq!(
            verifier()
                .verify(&claim("partner-x", "k-7f3a9c2e51d84b61"))
                .expect("verified"),
            Verified::Refused
        );
    }

    #[test]
    fn an_expired_key_is_refused_saying_when_it_expired() {
        let failure = verifier()
            .verify(&claim("partner-z", "k-expired-yesterday"))
            .expect_err("refused");
        assert_eq!(
            failure.message,
            format!(
                "the key 'partner-z' expired at {} and it is {NOW}",
                NOW - 86_400
            )
        );
        // The moment of expiry is already too late.
        let at_expiry = ApiKeyAuthenticator::new(verifier().store().clone())
            .with_clock(|| NOW + 60)
            .verify(&claim("partner-y", "k-0badc0de0badc0de"))
            .expect_err("refused");
        assert!(
            at_expiry.message.contains("expired"),
            "{}",
            at_expiry.message
        );
    }

    #[test]
    fn a_name_is_only_where_to_look_and_never_the_proof() {
        let verifier = verifier();
        // A good key under another key's name proves nothing about that name.
        assert_eq!(
            verifier
                .verify(&claim("partner-y", "k-7f3a9c2e51d84b60"))
                .expect("verified"),
            Verified::Refused
        );
        // Nor does a name the store holds with a key it does not.
        let digest = digest_of_partner_x(&verifier);
        assert_eq!(
            verifier.verify(&claim(&digest, "guess")).expect("verified"),
            Verified::Refused
        );
        let empty = verifier
            .verify(&claim("partner-x", ""))
            .expect_err("refused");
        assert!(empty.message.contains("empty"), "{}", empty.message);
    }

    #[test]
    fn a_missing_proof_and_another_mechanism_are_refused_by_name() {
        let bare = Presented::passed(mechanism::api_key(), "partner-x");
        let failure = verifier().verify(&bare).expect_err("refused");
        assert!(
            failure.message.contains("'api-key' proof"),
            "{}",
            failure.message
        );

        let bearer = Presented::passed(mechanism::bearer(), "mF_9.B5f…")
            .with_proof("bearer.token", "mF_9.B5f-4.1JqM");
        let failure = verifier().verify(&bearer).expect_err("refused");
        assert!(failure.message.contains("'bearer'"), "{}", failure.message);
    }

    struct Registry;

    impl PartyRegistry for Registry {
        fn resolve(&self, mechanism: &str, _purpose: Purpose, value: &str) -> Option<PartyId> {
            (mechanism == "api-key" && value == "partner-x").then(|| PartyId::new(11))
        }
    }

    #[test]
    fn through_the_gate_a_proven_key_resolves_to_its_party_and_stays_off_the_record() {
        let verifier = verifier();
        let acceptance = Acceptance::closed().accepting(&mechanism::api_key());
        let presented = claim("partner-x", "k-7f3a9c2e51d84b60");
        assert!(!format!("{presented:?}").contains("k-7f3a9c2e51d84b60"));

        let identity =
            authenticate(&acceptance, &[&verifier], &Registry, &presented).expect("accepted");
        assert_eq!(identity.party_id, Some(PartyId::new(11)));
        assert_eq!(identity.verified, Verified::Proven);

        let expired = claim("partner-z", "k-expired-yesterday");
        let refusal =
            authenticate(&acceptance, &[&verifier], &Registry, &expired).expect_err("refused");
        assert!(
            matches!(&refusal, Refusal::NotProven { detail, .. } if detail.contains("expired")),
            "{refusal}"
        );
    }
}
