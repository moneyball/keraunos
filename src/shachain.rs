//! BOLT 3 per-commitment secrets: generation from a seed and the
//! 49-slot compact storage scheme for the counterparty's revealed secrets.
//!
//! Indices count *down* from `2^48 - 1` (the first commitment) — the
//! direction that makes each newly revealed secret able to derive all
//! previously revealed ones below its bucket.

use crate::crypto::sha256::Sha256;

pub const MAX_INDEX: u64 = (1 << 48) - 1;

/// Map a commitment number (0, 1, 2, ...) to its shachain index.
pub fn index_for_commitment(commitment_number: u64) -> u64 {
    MAX_INDEX - commitment_number
}

fn flip_bit(p: &mut [u8; 32], bit: u8) {
    p[(bit / 8) as usize] ^= 1 << (bit % 8);
}

/// `derive_secret` from the spec: works for any `base` whose index shares
/// bits `bits..48` with `index`.
fn derive_secret(base: &[u8; 32], bits: u8, index: u64) -> [u8; 32] {
    let mut p = *base;
    for b in (0..bits).rev() {
        if index & (1 << b) != 0 {
            flip_bit(&mut p, b);
            p = Sha256::digest(&p);
        }
    }
    p
}

/// `generate_from_seed`: the sender-side generator.
pub fn generate_from_seed(seed: &[u8; 32], index: u64) -> [u8; 32] {
    derive_secret(seed, 48, index)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InsertError;

impl core::fmt::Display for InsertError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_str("per-commitment secret inconsistent with previously revealed secrets")
    }
}

impl std::error::Error for InsertError {}

/// Compact receiver-side storage: one (index, secret) pair per bucket,
/// bucket = number of trailing zero bits of the index.
#[derive(Clone)]
pub struct SecretStore {
    known: [Option<(u64, [u8; 32])>; 49],
}

impl Default for SecretStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretStore {
    pub fn new() -> SecretStore {
        SecretStore { known: [None; 49] }
    }

    fn bucket(index: u64) -> u8 {
        if index == 0 {
            48
        } else {
            index.trailing_zeros() as u8
        }
    }

    /// Insert a newly revealed secret, verifying it can re-derive every
    /// secret in the lower buckets (i.e. the peer isn't lying about its
    /// chain). The spec's `insert_secret`.
    pub fn insert(&mut self, index: u64, secret: [u8; 32]) -> Result<(), InsertError> {
        let b = Self::bucket(index);
        for lower in 0..b {
            if let Some((known_index, known_secret)) = self.known[lower as usize] {
                if derive_secret(&secret, b, known_index) != known_secret {
                    return Err(InsertError);
                }
            }
        }
        self.known[b as usize] = Some((index, secret));
        Ok(())
    }

    /// Derive the secret for `index` if any stored bucket covers it.
    pub fn secret_for(&self, index: u64) -> Option<[u8; 32]> {
        for b in 0..=48u8 {
            if let Some((known_index, known_secret)) = self.known[b as usize] {
                let mask = if b == 48 { 0 } else { !((1u64 << b) - 1) };
                if index & mask == known_index & mask && index >= known_index {
                    return Some(derive_secret(&known_secret, b, index));
                }
            }
        }
        None
    }

    /// Lowest (most recent) index stored, if any secret has been received.
    pub fn min_index(&self) -> Option<u64> {
        self.known.iter().flatten().map(|(i, _)| *i).min()
    }

    /// Serialize all occupied buckets (for persistence).
    pub fn entries(&self) -> Vec<(u64, [u8; 32])> {
        self.known.iter().flatten().copied().collect()
    }

    pub fn from_entries(entries: &[(u64, [u8; 32])]) -> SecretStore {
        let mut store = SecretStore::new();
        for (index, secret) in entries {
            store.known[Self::bucket(*index) as usize] = Some((*index, *secret));
        }
        store
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::hex;

    fn h(s: &str) -> [u8; 32] {
        hex::decode_array(s).unwrap()
    }

    // BOLT 3 Appendix D generation tests.
    #[test]
    fn generation_vectors() {
        let cases = [
            (
                [0u8; 32],
                281474976710655u64,
                "02a40c85b6f28da08dfdbe0926c53fab2de6d28c10301f8f7c4073d5e42e3148",
            ),
            (
                [0xffu8; 32],
                281474976710655,
                "7cc854b54e3e0dcdb010d7a3fee464a9687be6e8db3be6854c475621e007a5dc",
            ),
            (
                [0xffu8; 32],
                0xaaaaaaaaaaa,
                "56f4008fb007ca9acf0e15b054d5c9fd12ee06cea347914ddbaed70d1c13a528",
            ),
            (
                [0xffu8; 32],
                0x555555555555,
                "9015daaeb06dba4ccc05b91b2f73bd54405f2be9f217fbacd3c5ac2e62327d31",
            ),
            (
                [0x01u8; 32],
                1,
                "915c75942a26bb3a433a8ce2cb0427c29ec6c1775cfc78328b57f6ba7bfeaa9c",
            ),
        ];
        for (seed, index, want) in cases {
            assert_eq!(hex::encode(&generate_from_seed(&seed, index)), want);
        }
    }

    // BOLT 3 Appendix D storage tests: correct sequence inserts cleanly,
    // and the store can reproduce every secret afterward.
    #[test]
    fn storage_correct_sequence() {
        let secrets = [
            "7cc854b54e3e0dcdb010d7a3fee464a9687be6e8db3be6854c475621e007a5dc",
            "c7518c8ae4660ed02894df8976fa1a3659c1a8b4b5bec0c4b872abeba4cb8964",
            "2273e227a5b7449b6e70f1fb4652864038b1cbf9cd7c043a7d6456b7fc275ad8",
            "27cddaa5624534cb6cb9d7da077cf2b22ab21e9b506fd4998a51d54502e99116",
            "c65716add7aa98ba7acb236352d665cab17345fe45b55fb879ff80e6bd0c41dd",
            "969660042a28f32d9be17344e09374b379962d03db1574df5a8a5a47e19ce3f2",
            "a5a64476122ca0925fb344bdc1854c1c0a59fc614298e50a33e331980a220f32",
            "05cde6323d949933f7f7b78776bcc1ea6d9b31447732e3802e1f7ac44b650e17",
        ];
        let mut store = SecretStore::new();
        for (i, secret) in secrets.iter().enumerate() {
            store.insert(MAX_INDEX - i as u64, h(secret)).unwrap();
        }
        // Every secret must be recoverable.
        for (i, secret) in secrets.iter().enumerate() {
            assert_eq!(store.secret_for(MAX_INDEX - i as u64), Some(h(secret)), "secret {i}");
        }
        // Persistence roundtrip.
        let restored = SecretStore::from_entries(&store.entries());
        for (i, secret) in secrets.iter().enumerate() {
            assert_eq!(restored.secret_for(MAX_INDEX - i as u64), Some(h(secret)));
        }
        assert_eq!(store.min_index(), Some(MAX_INDEX - 7));
    }

    // The 8 "insert_secret #N incorrect" sequences. Each entry is
    // (secrets..., index_of_failure).
    #[test]
    fn storage_incorrect_sequences() {
        let cases: [(&[&str], usize); 8] = [
            (&[
                "02a40c85b6f28da08dfdbe0926c53fab2de6d28c10301f8f7c4073d5e42e3148",
                "c7518c8ae4660ed02894df8976fa1a3659c1a8b4b5bec0c4b872abeba4cb8964",
            ], 1),
            (&[
                "02a40c85b6f28da08dfdbe0926c53fab2de6d28c10301f8f7c4073d5e42e3148",
                "dddc3a8d14fddf2b68fa8c7fbad2748274937479dd0f8930d5ebb4ab6bd866a3",
                "2273e227a5b7449b6e70f1fb4652864038b1cbf9cd7c043a7d6456b7fc275ad8",
                "27cddaa5624534cb6cb9d7da077cf2b22ab21e9b506fd4998a51d54502e99116",
            ], 3),
            (&[
                "7cc854b54e3e0dcdb010d7a3fee464a9687be6e8db3be6854c475621e007a5dc",
                "c7518c8ae4660ed02894df8976fa1a3659c1a8b4b5bec0c4b872abeba4cb8964",
                "c51a18b13e8527e579ec56365482c62f180b7d5760b46e9477dae59e87ed423a",
                "27cddaa5624534cb6cb9d7da077cf2b22ab21e9b506fd4998a51d54502e99116",
            ], 3),
            (&[
                "02a40c85b6f28da08dfdbe0926c53fab2de6d28c10301f8f7c4073d5e42e3148",
                "dddc3a8d14fddf2b68fa8c7fbad2748274937479dd0f8930d5ebb4ab6bd866a3",
                "c51a18b13e8527e579ec56365482c62f180b7d5760b46e9477dae59e87ed423a",
                "ba65d7b0ef55a3ba300d4e87af29868f394f8f138d78a7011669c79b37b936f4",
                "c65716add7aa98ba7acb236352d665cab17345fe45b55fb879ff80e6bd0c41dd",
                "969660042a28f32d9be17344e09374b379962d03db1574df5a8a5a47e19ce3f2",
                "a5a64476122ca0925fb344bdc1854c1c0a59fc614298e50a33e331980a220f32",
                "05cde6323d949933f7f7b78776bcc1ea6d9b31447732e3802e1f7ac44b650e17",
            ], 7),
            (&[
                "7cc854b54e3e0dcdb010d7a3fee464a9687be6e8db3be6854c475621e007a5dc",
                "c7518c8ae4660ed02894df8976fa1a3659c1a8b4b5bec0c4b872abeba4cb8964",
                "2273e227a5b7449b6e70f1fb4652864038b1cbf9cd7c043a7d6456b7fc275ad8",
                "27cddaa5624534cb6cb9d7da077cf2b22ab21e9b506fd4998a51d54502e99116",
                "631373ad5f9ef654bb3dade742d09504c567edd24320d2fcd68e3cc47e2ff6a6",
                "969660042a28f32d9be17344e09374b379962d03db1574df5a8a5a47e19ce3f2",
            ], 5),
            (&[
                "7cc854b54e3e0dcdb010d7a3fee464a9687be6e8db3be6854c475621e007a5dc",
                "c7518c8ae4660ed02894df8976fa1a3659c1a8b4b5bec0c4b872abeba4cb8964",
                "2273e227a5b7449b6e70f1fb4652864038b1cbf9cd7c043a7d6456b7fc275ad8",
                "27cddaa5624534cb6cb9d7da077cf2b22ab21e9b506fd4998a51d54502e99116",
                "631373ad5f9ef654bb3dade742d09504c567edd24320d2fcd68e3cc47e2ff6a6",
                "b7e76a83668bde38b373970155c868a653304308f9896692f904a23731224bb1",
                "a5a64476122ca0925fb344bdc1854c1c0a59fc614298e50a33e331980a220f32",
                "05cde6323d949933f7f7b78776bcc1ea6d9b31447732e3802e1f7ac44b650e17",
            ], 7),
            (&[
                "7cc854b54e3e0dcdb010d7a3fee464a9687be6e8db3be6854c475621e007a5dc",
                "c7518c8ae4660ed02894df8976fa1a3659c1a8b4b5bec0c4b872abeba4cb8964",
                "2273e227a5b7449b6e70f1fb4652864038b1cbf9cd7c043a7d6456b7fc275ad8",
                "27cddaa5624534cb6cb9d7da077cf2b22ab21e9b506fd4998a51d54502e99116",
                "c65716add7aa98ba7acb236352d665cab17345fe45b55fb879ff80e6bd0c41dd",
                "969660042a28f32d9be17344e09374b379962d03db1574df5a8a5a47e19ce3f2",
                "e7971de736e01da8ed58b94c2fc216cb1dca9e326f3a96e7194fe8ea8af6c0a3",
                "05cde6323d949933f7f7b78776bcc1ea6d9b31447732e3802e1f7ac44b650e17",
            ], 7),
            (&[
                "7cc854b54e3e0dcdb010d7a3fee464a9687be6e8db3be6854c475621e007a5dc",
                "c7518c8ae4660ed02894df8976fa1a3659c1a8b4b5bec0c4b872abeba4cb8964",
                "2273e227a5b7449b6e70f1fb4652864038b1cbf9cd7c043a7d6456b7fc275ad8",
                "27cddaa5624534cb6cb9d7da077cf2b22ab21e9b506fd4998a51d54502e99116",
                "c65716add7aa98ba7acb236352d665cab17345fe45b55fb879ff80e6bd0c41dd",
                "969660042a28f32d9be17344e09374b379962d03db1574df5a8a5a47e19ce3f2",
                "a5a64476122ca0925fb344bdc1854c1c0a59fc614298e50a33e331980a220f32",
                "a7efbc61aac46d34f77778bac22c8a20c6a46ca460addc49009bda875ec88fa4",
            ], 7),
        ];

        for (case_idx, (secrets, fail_at)) in cases.iter().enumerate() {
            let mut store = SecretStore::new();
            for (i, secret) in secrets.iter().enumerate() {
                let result = store.insert(MAX_INDEX - i as u64, h(secret));
                if i == *fail_at {
                    assert_eq!(result, Err(InsertError), "case {case_idx} step {i} must fail");
                } else {
                    assert_eq!(result, Ok(()), "case {case_idx} step {i} must succeed");
                }
            }
        }
    }
}
