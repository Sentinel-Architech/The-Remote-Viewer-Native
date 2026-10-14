//! Native hardware abstraction for phone capabilities.
//!
//! Per spec, everything a phone uses to communicate must be native:
//! the camera (required for AR), phone calling, GPS, text messaging,
//! and the rest. These are traits and in-process stub
//! implementations — API-stable, zero external dependencies, no
//! corporate SDKs, no network I/O.
//!
//! Real platform bindings (e.g. GrapheneOS native camera/GNSS paths)
//! plug in behind these same traits later.

/// An image frame captured natively. Stub: metadata only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame {
    /// Frame width in pixels.
    pub width: u32,
    /// Frame height in pixels.
    pub height: u32,
    /// Local capture sequence number.
    pub sequence: u64,
}

/// Errors for hardware operations. All local; no I/O.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HwError {
    /// The capability is unavailable on this device (stub).
    Unavailable,
    /// The request was malformed.
    InvalidRequest,
}

impl HwError {
    /// Short machine-readable label.
    pub fn label(self) -> &'static str {
        match self {
            HwError::Unavailable => "unavailable",
            HwError::InvalidRequest => "invalid-request",
        }
    }
}

/// Native camera access. Required for AR. Stub returns synthetic
/// frame metadata only.
pub trait Camera {
    /// Capture a single frame's metadata natively.
    fn capture_frame(&mut self) -> Result<Frame, HwError>;
    /// Whether the camera is currently available.
    fn is_available(&self) -> bool;
}

/// Native phone calling.
pub trait Phone {
    /// Place a call to a local contact identifier. Stub: local-only
    /// placeholder, no actual call is placed.
    fn dial(&mut self, contact: &str) -> Result<(), HwError>;
}

/// Native GPS / location.
pub trait Gps {
    /// Latest latitude/longitude, in degrees. Stub returns a fixed
    /// local placeholder (not a real fix).
    fn location(&self) -> Result<(f64, f64), HwError>;
}

/// Native text messaging.
pub trait Texting {
    /// Queue a text message locally for a contact. Stub: local-only
    /// placeholder, no message is sent.
    fn send_text(&mut self, contact: &str, body: &str) -> Result<(), HwError>;
}

/// Native short-range proximity (e.g. NFC/BLE) for contact sharing
/// and the ~1-mile local identity exchange. Stub only.
pub trait Proximity {
    /// Broadcast the local identity beacon natively. Stub: no-op.
    fn beacon(&mut self) -> Result<(), HwError>;
    /// Whether a peer is in range. Stub: always false.
    fn peer_in_range(&self) -> bool;
}

/// In-process stub implementing every hardware trait. Used for
/// compile-time and unit-style checks until real platform bindings
/// exist.
#[derive(Debug, Clone, Default)]
pub struct NativeHwStub {
    frames_captured: u64,
}

impl NativeHwStub {
    /// Create a fresh stub.
    pub fn new() -> Self {
        NativeHwStub {
            frames_captured: 0,
        }
    }

    /// How many frames have been captured via this stub.
    pub fn frames_captured(&self) -> u64 {
        self.frames_captured
    }
}

impl Camera for NativeHwStub {
    fn capture_frame(&mut self) -> Result<Frame, HwError> {
        if !self.is_available() {
            return Err(HwError::Unavailable);
        }
        self.frames_captured += 1;
        Ok(Frame {
            width: 640,
            height: 480,
            sequence: self.frames_captured,
        })
    }

    fn is_available(&self) -> bool {
        true
    }
}

impl Phone for NativeHwStub {
    fn dial(&mut self, contact: &str) -> Result<(), HwError> {
        if contact.is_empty() {
            return Err(HwError::InvalidRequest);
        }
        Ok(())
    }
}

impl Gps for NativeHwStub {
    fn location(&self) -> Result<(f64, f64), HwError> {
        // Stub placeholder: 0.0/0.0 is never a real fix.
        Ok((0.0, 0.0))
    }
}

impl Texting for NativeHwStub {
    fn send_text(&mut self, contact: &str, body: &str) -> Result<(), HwError> {
        if contact.is_empty() || body.is_empty() {
            return Err(HwError::InvalidRequest);
        }
        Ok(())
    }
}

impl Proximity for NativeHwStub {
    fn beacon(&mut self) -> Result<(), HwError> {
        Ok(())
    }

    fn peer_in_range(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_implements_every_hardware_trait() {
        fn use_camera(_: &impl Camera) {}
        fn use_phone(_: &impl Phone) {}
        fn use_gps(_: &impl Gps) {}
        fn use_texting(_: &impl Texting) {}
        fn use_proximity(_: &impl Proximity) {}
        let stub = NativeHwStub::new();
        use_camera(&stub);
        use_phone(&stub);
        use_gps(&stub);
        use_texting(&stub);
        use_proximity(&stub);
    }

    #[test]
    fn camera_capture_returns_frame_and_counts() {
        let mut stub = NativeHwStub::new();
        assert!(stub.is_available());
        let f1 = stub.capture_frame().expect("camera available");
        assert_eq!(f1.width, 640);
        assert_eq!(f1.height, 480);
        let f2 = stub.capture_frame().expect("camera available");
        assert!(f2.sequence > f1.sequence);
        assert_eq!(stub.frames_captured(), 2);
        let f3 = NativeHwStub::default().capture_frame().expect("ok");
        assert_eq!(f3.sequence, 1);
    }

    #[test]
    fn hw_error_labels_are_stable() {
        assert_eq!(HwError::Unavailable.label(), "unavailable");
        assert_eq!(HwError::InvalidRequest.label(), "invalid-request");
        assert_eq!(HwError::Unavailable, HwError::Unavailable);
        assert_ne!(HwError::Unavailable, HwError::InvalidRequest);
    }

    #[test]
    fn phone_and_texting_reject_empty_requests() {
        let mut stub = NativeHwStub::new();
        assert_eq!(stub.dial(""), Err(HwError::InvalidRequest));
        assert!(stub.dial("555-0100").is_ok());
        assert_eq!(
            stub.send_text("", "hello"),
            Err(HwError::InvalidRequest)
        );
        assert_eq!(
            stub.send_text("555-0100", ""),
            Err(HwError::InvalidRequest)
        );
        assert!(stub.send_text("555-0100", "hello").is_ok());
    }

    #[test]
    fn gps_and_proximity_stub_behaviors() {
        let mut stub = NativeHwStub::new();
        let (lat, lon) = stub.location().expect("stub location");
        assert_eq!((lat, lon), (0.0, 0.0));
        assert!(stub.beacon().is_ok());
        assert!(!stub.peer_in_range());
    }
}
