//! Optical air-gap transport.
//!
//! Path: age (encrypt-first) -> Soliton LT fountain -> TRVL framing ->
//! optical QR. Interop standard: TRVL1 magic + CRC-16.
//!
//! This module implements the real TRVL1 wire framing: every frame
//! carries a CRC-16-CCITT (poly 0x1021, init 0xFFFF) over the body so
//! corrupted optical reads are rejected locally. The fountain-code and
//! encryption layers still land on top later; the framing API is
//! stable for them.

/// Wire magic for the TRVL text form.
pub const TRVL_MAGIC: &str = "TRVL1";

/// CRC-16-CCITT (poly 0x1021, init 0xFFFF) over `data`.
///
/// Small, deterministic, dependency-free integrity check for optical
/// frames. Catches accidental corruption (bad reads, glare); it is
/// not a cryptographic MAC.
pub fn crc16_ccitt(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &b in data {
        crc ^= (u16::from(b)) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    crc
}

/// Sender optical profile (frames per second).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AirgapProfile {
    /// 1 fps — high loss / poor light.
    Safe,
    /// 2 fps — default.
    Normal,
    /// 4 fps — good light + stable mount.
    Fast,
}

impl AirgapProfile {
    /// Frames per second for this profile.
    pub fn fps(self) -> u32 {
        match self {
            AirgapProfile::Safe => 1,
            AirgapProfile::Normal => 2,
            AirgapProfile::Fast => 4,
        }
    }
}

/// A TRVL1 frame: magic + CRC-16 over the body + payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrvlFrame {
    /// Frame body bytes (already encrypted/fountain-coded upstream).
    pub payload: Vec<u8>,
}

impl TrvlFrame {
    /// Wire magic for the text form: `TRVL1.` + hex(frame bytes).
    pub fn magic() -> &'static str {
        TRVL_MAGIC
    }

    /// Build a frame around `payload`.
    pub fn new(payload: Vec<u8>) -> Self {
        TrvlFrame { payload }
    }

    /// CRC-16-CCITT over this frame's body.
    pub fn crc(&self) -> u16 {
        crc16_ccitt(&self.payload)
    }

    /// Encode to the wire text form: `TRVL1.` + hex(magic + CRC + payload).
    ///
    /// Layout of the encoded bytes: the 5 ASCII bytes of `TRVL1`,
    /// then the 2-byte big-endian CRC-16 of the payload, then the
    /// payload itself — all rendered as lowercase hex.
    pub fn encode(&self) -> String {
        let mut raw = Vec::with_capacity(TRVL_MAGIC.len() + 2 + self.payload.len());
        raw.extend_from_slice(TRVL_MAGIC.as_bytes());
        raw.extend_from_slice(&self.crc().to_be_bytes());
        raw.extend_from_slice(&self.payload);
        let hex: String = raw.iter().map(|b| format!("{:02x}", b)).collect();
        format!("{}.{}", TRVL_MAGIC, hex)
    }

    /// Decode a wire text form produced by [`TrvlFrame::encode`].
    ///
    /// Rejects wrong magic, malformed hex, and CRC mismatches
    /// (corrupted optical reads). Pure local computation.
    ///
    /// Hex case: decode accepts upper- and lowercase hex digits;
    /// [`TrvlFrame::encode`] always emits lowercase.
    pub fn decode(text: &str) -> Result<Self, &'static str> {
        let hex = text.strip_prefix(&format!("{}.", TRVL_MAGIC)).ok_or("bad magic")?;
        if hex.len() % 2 != 0 {
            return Err("odd hex length");
        }
        let raw: Vec<u8> = hex
            .as_bytes()
            .chunks(2)
            .map(|pair| {
                let hi = (pair[0] as char).to_digit(16).ok_or("bad hex")?;
                let lo = (pair[1] as char).to_digit(16).ok_or("bad hex")?;
                Ok((hi * 16 + lo) as u8)
            })
            .collect::<Result<Vec<u8>, &'static str>>()?;
        if raw.len() < TRVL_MAGIC.len() + 2 {
            return Err("frame too short");
        }
        if &raw[..TRVL_MAGIC.len()] != TRVL_MAGIC.as_bytes() {
            return Err("bad magic");
        }
        let crc = u16::from_be_bytes([raw[TRVL_MAGIC.len()], raw[TRVL_MAGIC.len() + 1]]);
        let payload = raw[TRVL_MAGIC.len() + 2..].to_vec();
        if crc16_ccitt(&payload) != crc {
            return Err("crc mismatch");
        }
        Ok(TrvlFrame { payload })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_is_trvl1_wire_marker() {
        assert_eq!(TrvlFrame::magic(), "TRVL1");
        assert_eq!(TRVL_MAGIC, "TRVL1");
    }

    #[test]
    fn frame_preserves_payload() {
        let payload = vec![0x01, 0x02, 0xFE, 0xFF];
        let frame = TrvlFrame::new(payload.clone());
        assert_eq!(frame.payload, payload);
    }

    #[test]
    fn empty_payload_frame_round_trips() {
        let frame = TrvlFrame::new(Vec::new());
        assert!(frame.payload.is_empty());
        assert_eq!(TrvlFrame::decode(&frame.encode()).unwrap(), frame);
    }

    #[test]
    fn large_payload_stored_intact() {
        // Chunking-sized payloads must survive the stub frame untouched.
        let payload: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
        let frame = TrvlFrame::new(payload.clone());
        assert_eq!(frame.payload.len(), 4096);
        assert_eq!(frame.payload, payload);
        assert_eq!(frame.clone().payload, payload);
    }

    #[test]
    fn profiles_map_to_expected_fps() {
        assert_eq!(AirgapProfile::Safe.fps(), 1);
        assert_eq!(AirgapProfile::Normal.fps(), 2);
        assert_eq!(AirgapProfile::Fast.fps(), 4);
        assert!(AirgapProfile::Safe.fps() < AirgapProfile::Normal.fps());
        assert!(AirgapProfile::Normal.fps() < AirgapProfile::Fast.fps());
    }

    #[test]
    fn crc16_ccitt_matches_known_vector() {
        // "123456789" -> 0x29B1 for CRC-16-CCITT-FALSE.
        assert_eq!(crc16_ccitt(b"123456789"), 0x29B1);
        assert_eq!(crc16_ccitt(b""), 0xFFFF);
    }

    #[test]
    fn encode_decode_round_trip() {
        for payload in [
            vec![],
            vec![0x01, 0x02, 0xFE, 0xFF],
            (0..4096).map(|i| (i % 251) as u8).collect::<Vec<u8>>(),
        ] {
            let frame = TrvlFrame::new(payload.clone());
            let wire = frame.encode();
            assert!(wire.starts_with("TRVL1."));
            let back = TrvlFrame::decode(&wire).expect("valid frame decodes");
            assert_eq!(back.payload, payload);
        }
    }

    #[test]
    fn decode_rejects_corrupted_frames() {
        let frame = TrvlFrame::new(b"optical payload".to_vec());
        let wire = frame.encode();
        // Flip one hex nibble in the payload region.
        let mut bad: Vec<char> = wire.chars().collect();
        let last = bad.len() - 1;
        bad[last] = if bad[last] == '0' { '1' } else { '0' };
        let corrupted: String = bad.into_iter().collect();
        assert_eq!(TrvlFrame::decode(&corrupted), Err("crc mismatch"));
    }

    #[test]
    fn decode_rejects_wrong_magic_and_garbage() {
        assert_eq!(TrvlFrame::decode("NOPE.00"), Err("bad magic"));
        assert_eq!(TrvlFrame::decode("TRVL1.zz"), Err("bad hex"));
        assert_eq!(TrvlFrame::decode("TRVL1.abc"), Err("odd hex length"));
        assert_eq!(TrvlFrame::decode(""), Err("bad magic"));
    }
}
