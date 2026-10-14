//! E2E reverse-inverted scramble QR.
//!
//! Each Remote Viewer shares this only with chosen contacts via camera.
//! On-device only.
//!
//! The scramble transform here is *obfuscation, not encryption*:
//! the payload is byte-reversed ("reverse") and bitwise-inverted
//! ("inverted"), which `unseal` reverses exactly. Real
//! `age`-encrypted (MIT/Apache-2.0) sealing replaces this transform
//! behind the stable [`ScrambleQr`] API before any production use.
//! The integrity tag is FNV-1a (see [`crate::crypto::fnv1a64`]) — a
//! check value, not a MAC.

use crate::crypto::fnv1a64_hex;

/// A sealed, reverse-inverted scramble packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScrambleQr {
    /// Integrity tag of the *original* plaintext (FNV-1a hex, 16 chars).
    pub payload_tag: String,
    /// Reverse-inverted scramble flag: always true per spec.
    pub inverted: bool,
    /// Scrambled payload bytes: `plaintext` reversed, then bitwise-NOT.
    pub scrambled: Vec<u8>,
}

impl ScrambleQr {
    /// Seal `plaintext` into a scramble packet.
    ///
    /// Applies the reverse-inverted scramble (reverse byte order, then
    /// bitwise NOT) and tags the original bytes with FNV-1a. The tag is
    /// verified on [`ScrambleQr::unseal`]; this API stays stable when
    /// real `age` encryption replaces the transform.
    pub fn seal(plaintext: &[u8]) -> Self {
        let scrambled: Vec<u8> = plaintext.iter().rev().map(|b| !b).collect();
        ScrambleQr {
            payload_tag: fnv1a64_hex(plaintext),
            inverted: true,
            scrambled,
        }
    }

    /// Reverse the scramble, recovering the original bytes.
    ///
    /// Returns `None` when the integrity tag does not match the
    /// recovered plaintext — i.e. the packet was tampered with or
    /// corrupted. Pure local computation; no I/O.
    pub fn unseal(&self) -> Option<Vec<u8>> {
        let recovered: Vec<u8> = self.scrambled.iter().rev().map(|b| !b).collect();
        if fnv1a64_hex(&recovered) != self.payload_tag {
            return None;
        }
        Some(recovered)
    }

    /// The reverse-inverted scramble flag. Per spec this is always true.
    pub fn is_inverted(&self) -> bool {
        self.inverted
    }

    /// Length of the scrambled payload in bytes.
    pub fn payload_len(&self) -> usize {
        self.scrambled.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_marks_packet_reverse_inverted() {
        // Per spec: the reverse-inverted scramble flag is always true.
        let qr = ScrambleQr::seal(b"hello");
        assert!(qr.inverted);
        assert!(qr.is_inverted());
    }

    #[test]
    fn seal_is_deterministic_for_same_plaintext() {
        // Determinism doubles as the integrity-tag "round trip":
        // re-sealing the same bytes must reproduce the same tag.
        let a = ScrambleQr::seal(b"contact key material");
        let b = ScrambleQr::seal(b"contact key material");
        assert_eq!(a.payload_tag, b.payload_tag);
        assert_eq!(a.scrambled, b.scrambled);
    }

    #[test]
    fn seal_tag_is_16_lowercase_hex_chars() {
        let qr = ScrambleQr::seal(b"hello");
        assert_eq!(qr.payload_tag.len(), 16);
        assert!(qr
            .payload_tag
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn empty_input_seals_to_fnv_offset_basis() {
        let qr = ScrambleQr::seal(b"");
        assert_eq!(qr.payload_tag, "cbf29ce484222325");
        assert!(qr.is_inverted());
        assert!(qr.scrambled.is_empty());
        assert_eq!(qr.unseal(), Some(Vec::new()));
    }

    #[test]
    fn single_byte_change_changes_tag() {
        let a = ScrambleQr::seal(b"hello");
        let b = ScrambleQr::seal(b"hellp");
        assert_ne!(a.payload_tag, b.payload_tag);
    }

    #[test]
    fn unseal_round_trips_arbitrary_payloads() {
        for payload in [
            b"hello".as_slice(),
            b"".as_slice(),
            &[0x00, 0xFF, 0x01, 0xFE, 0x80],
            b"The Remote Viewer contact exchange packet, v1",
        ] {
            let qr = ScrambleQr::seal(payload);
            assert_eq!(qr.payload_len(), payload.len());
            assert_eq!(
                qr.unseal().as_deref(),
                Some(payload),
                "round trip failed for {:?}",
                payload
            );
        }
    }

    #[test]
    fn unseal_rejects_tampered_tag() {
        let mut qr = ScrambleQr::seal(b"hello");
        qr.payload_tag = "0".repeat(16);
        assert_eq!(qr.unseal(), None);
    }

    #[test]
    fn unseal_rejects_tampered_payload() {
        let mut qr = ScrambleQr::seal(b"hello");
        qr.scrambled[0] ^= 0x01;
        assert_eq!(qr.unseal(), None);
    }

    #[test]
    fn scramble_is_reverse_then_invert_of_plaintext() {
        // The transform is exactly: reverse byte order, then bitwise NOT.
        let qr = ScrambleQr::seal(&[0x01, 0x02, 0x03]);
        assert_eq!(qr.scrambled, vec![!0x03, !0x02, !0x01]);
    }
}
