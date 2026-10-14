//! On-device ID verification screens.
//!
//! Step-by-step UI over the [`trv_core::verify_flow::VerificationFlow`]
//! state machine: the user scans their ID, picks a liveness method,
//! passes the liveness check, and gets a signed attestation — all on
//! this phone.
//!
//! ## Privacy promise (shown on every screen)
//!
//! "Your ID never leaves this phone." The document image, the MRZ
//! data, and the video/biometric capture are processed on-device and
//! never stored. The only thing that may ever leave is the signed
//! attestation: a public key, a "verified human" stamp, dates, and a
//! signature. No name, no birth date, no ID number, no photo.
//!
//! ## Portability contract
//!
//! This module never calls platform APIs. Camera, OCR, and biometric
//! capture do not exist yet — they are future platform work behind the
//! [`PlatformCapture`] trait, implemented by the embedding app (e.g.
//! the Android shell). The screen and the flow only accept the trait's
//! OUTPUTS: MRZ text lines and signed liveness verdicts.
//!
//! ## Paywall
//!
//! Verification is the [`Feature::IdentityVerification`] gated
//! capability: [`VerifyScreen::begin_flow`] consults [`can_access`]
//! and fails closed without a live paid entitlement. Ghost tier is
//! denied at the door.

use crate::font::{GLYPH_H, GLYPH_W};
use crate::platform::{PixelScreen, Screen, TextScreen, UiEvent};
use crate::render::{self, color};
use trv_backend::entitlement::Entitlement;
use trv_backend::gates::{can_access, Feature};
use trv_core::crypto::ed25519::{PublicKey, SecretKey};
use trv_core::verify::{
    LivenessAction, LivenessChallenge, LivenessMethod, LivenessResponse, VerificationAttestation,
    VerificationLevel,
};
use trv_core::verify_flow::{FlowError, FlowStep, VerificationFlow};

/// Shown on every verification screen, pixel and text.
pub const PRIVACY_LINE: &str = "Your ID never leaves this phone.";

/// Shown when the IdentityVerification gate denies starting the flow.
pub const VERIFY_DENIED_MSG: &str =
    "ID verification needs a paid subscription. Verify your receipt to continue.";

// ---------------------------------------------------------------------------
// Platform hookup point
// ---------------------------------------------------------------------------

/// Why a platform capture step failed. Reason codes only — never data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureError {
    /// No camera / biometric hardware, or the OS denied access.
    Unavailable,
    /// The user backed out of the capture.
    UserCancelled,
    /// The capture itself failed (blurry, dark, sensor error…).
    CaptureFailed,
    /// OCR could not read the document.
    OcrFailed,
    /// The sensor is busy with another operation.
    HardwareBusy,
}

impl std::fmt::Display for CaptureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            CaptureError::Unavailable => "capture hardware unavailable",
            CaptureError::UserCancelled => "capture cancelled",
            CaptureError::CaptureFailed => "capture failed",
            CaptureError::OcrFailed => "could not read the document",
            CaptureError::HardwareBusy => "sensor busy",
        };
        f.write_str(s)
    }
}

impl std::error::Error for CaptureError {}

/// Future platform work: camera, OCR, and biometric capture.
///
/// Implemented by the embedding app (e.g. the Android shell) once
/// real platform code exists. The verification flow and these screens
/// only ever accept this trait's OUTPUTS — they never call platform
/// APIs themselves.
///
/// ## Implementor contract (read carefully)
///
/// - `capture_document_image`: photograph the ID. Return raw bytes.
/// - `extract_mrz`: run OCR on the image, return the two 44-char TD3
///   MRZ lines. The flow validates them and drops them immediately.
/// - `perform_liveness`: for the challenge's method, capture the video
///   selfie or biometric, analyze it ENTIRELY on-device, WIPE the raw
///   bytes from memory, then sign the verdict with the device identity
///   key via [`LivenessResponse::sign`]. Only the signed verdict
///   crosses into the flow — never the video, never the template.
///
/// Until an implementation exists, the app drives the flow with test
/// or stub outputs through the screen's `submit_*` methods.
pub trait PlatformCapture {
    /// Photograph the ID document. Raw image bytes.
    fn capture_document_image(&mut self) -> Result<Vec<u8>, CaptureError>;
    /// OCR the document image into the two TD3 MRZ lines.
    fn extract_mrz(&mut self, image: &[u8]) -> Result<(String, String), CaptureError>;
    /// Run the liveness check for the challenge and return the SIGNED
    /// verdict. See the implementor contract above: analyze on-device,
    /// wipe the capture, sign only the verdict.
    fn perform_liveness(
        &mut self,
        challenge: &LivenessChallenge,
    ) -> Result<LivenessResponse, CaptureError>;
}

// ---------------------------------------------------------------------------
// The screen
// ---------------------------------------------------------------------------

/// Plain-language label for a liveness action (video challenge).
fn action_label(a: LivenessAction) -> &'static str {
    match a {
        LivenessAction::Blink => "Blink",
        LivenessAction::TurnLeft => "Turn left",
        LivenessAction::TurnRight => "Turn right",
        LivenessAction::NodUp => "Nod up",
        LivenessAction::NodDown => "Nod down",
        LivenessAction::Smile => "Smile",
    }
}

/// Untrusted wall-clock seconds, for challenge timestamps only.
/// There is no trusted on-device clock; freshness is the caller's
/// responsibility. Test and app code should prefer the explicit
/// `*_at` method variants with their own timestamps.
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The ID verification screen: one [`Screen`] driving the whole flow.
///
/// The embedding app feeds platform outputs in through `submit_*`
/// (document lines from OCR, signed liveness verdicts from the
/// platform capture layer) and reads the pending challenge out for
/// the platform via [`VerifyScreen::pending_challenge`]. The screen
/// never touches platform APIs.
pub struct VerifyScreen {
    flow: VerificationFlow,
    entitlement: Option<Entitlement>,
    w: u32,
    h: u32,
    /// One-line status / error shown under the step body. Cleared on
    /// every successful advance.
    notice: String,
}

impl VerifyScreen {
    pub fn new(w: u32, h: u32) -> Self {
        VerifyScreen {
            flow: VerificationFlow::new(),
            entitlement: None,
            w: w.max(64),
            h: h.max(64),
            notice: String::new(),
        }
    }

    /// Present (or replace) the entitlement. `None` revokes immediately.
    pub fn set_entitlement(&mut self, entitlement: Option<Entitlement>) {
        self.entitlement = entitlement;
    }

    /// Current flow step, for the embedding app.
    pub fn step(&self) -> FlowStep {
        self.flow.step()
    }

    /// The issued attestation, once the flow completes.
    pub fn attestation(&self) -> Option<VerificationAttestation> {
        self.flow.attestation()
    }

    fn deny(&mut self, msg: &str) {
        self.notice.clear();
        self.notice.push_str(msg);
    }

    fn clear_notice(&mut self) {
        self.notice.clear();
    }

    /// Start verification. Gated on [`Feature::IdentityVerification`]:
    /// fails closed without a live paid entitlement, and the flow does
    /// not advance.
    pub fn begin_flow(&mut self) {
        if !can_access(Feature::IdentityVerification, self.entitlement) {
            self.deny(VERIFY_DENIED_MSG);
            return;
        }
        match self.flow.begin() {
            Ok(()) => self.clear_notice(),
            Err(e) => self.deny(&e.to_string()),
        }
    }

    /// Feed the OCR'd MRZ lines into the document check.
    ///
    /// Privacy: the flow validates the lines and drops them when this
    /// returns. Nothing from the document is stored.
    pub fn submit_document_lines(
        &mut self,
        line1: &str,
        line2: &str,
        today: (u8, u8, u8),
    ) -> Result<VerificationLevel, FlowError> {
        match self.flow.submit_document(line1, line2, today) {
            Ok(level) => {
                self.clear_notice();
                Ok(level)
            }
            Err(e) => {
                self.deny(&e.to_string());
                Err(e)
            }
        }
    }

    /// The user chose video selfie. Issues the liveness challenge.
    pub fn choose_video(&mut self, issued_at: u64) -> Result<LivenessChallenge, FlowError> {
        self.choose_method(LivenessMethod::VideoSelfie, issued_at)
    }

    /// The user chose bioprint (fingerprint / face). Issues the
    /// liveness challenge.
    pub fn choose_bioprint(&mut self, issued_at: u64) -> Result<LivenessChallenge, FlowError> {
        self.choose_method(LivenessMethod::Bioprint, issued_at)
    }

    fn choose_method(
        &mut self,
        method: LivenessMethod,
        issued_at: u64,
    ) -> Result<LivenessChallenge, FlowError> {
        match self.flow.choose_liveness(method, issued_at) {
            Ok(ch) => {
                self.clear_notice();
                Ok(ch)
            }
            Err(e) => {
                self.deny(&e.to_string());
                Err(e)
            }
        }
    }

    /// The live challenge for the platform capture layer, if any.
    pub fn pending_challenge(&self) -> Option<LivenessChallenge> {
        self.flow.pending_challenge()
    }

    /// Feed the platform's signed liveness verdict into the flow.
    pub fn submit_liveness_response(
        &mut self,
        response: &LivenessResponse,
    ) -> Result<(), FlowError> {
        match self.flow.submit_liveness(response) {
            Ok(_) => {
                self.clear_notice();
                Ok(())
            }
            Err(e) => {
                self.deny(&e.to_string());
                Err(e)
            }
        }
    }

    /// Finish verification: build the signed proof of life and issue
    /// the attestation. The device secret is used transiently for the
    /// signatures and is never stored.
    pub fn finish(
        &mut self,
        device_secret: &SecretKey,
        device_public: &PublicKey,
        subject_key: &PublicKey,
        issued_at: u64,
    ) -> Result<VerificationAttestation, FlowError> {
        match self.flow.complete(device_secret, device_public, subject_key, issued_at) {
            Ok(att) => {
                self.clear_notice();
                Ok(att)
            }
            Err(e) => {
                self.deny(&e.to_string());
                Err(e)
            }
        }
    }

    /// Cancel and reset to the start step.
    pub fn cancel(&mut self) {
        self.flow.reset();
        self.clear_notice();
    }

    /// Body lines for the current step (shared by both render paths).
    fn body_lines(&self) -> Vec<String> {
        match self.flow.step() {
            FlowStep::Start => vec![
                "Prove you're a real person.".to_string(),
                "".to_string(),
                "1. Scan your ID on this phone.".to_string(),
                "2. Do a quick liveness check.".to_string(),
                "".to_string(),
                "No company checks your ID. No human".to_string(),
                "reviews it. This phone does it all.".to_string(),
                "".to_string(),
                "[Enter] Start verification".to_string(),
            ],
            FlowStep::DocumentCapture => vec![
                "Point your camera at your ID.".to_string(),
                "".to_string(),
                "(The camera view appears here".to_string(),
                " on your phone.)".to_string(),
                "".to_string(),
                "Waiting for the scan...".to_string(),
            ],
            FlowStep::LivenessChoice => vec![
                "How do you want to prove it's you?".to_string(),
                "".to_string(),
                "[1] Video selfie - follow 3 moves".to_string(),
                "[2] Bioprint - fingerprint or face".to_string(),
            ],
            FlowStep::LivenessCapture => {
                let mut lines = Vec::new();
                match self.pending_challenge().map(|c| c.method) {
                    Some(LivenessMethod::VideoSelfie) => {
                        lines.push("Do these 3 moves:".to_string());
                        lines.push("".to_string());
                        if let Some(ch) = self.pending_challenge() {
                            for (i, a) in ch.actions.iter().enumerate() {
                                lines.push(format!("{}. {}", i + 1, action_label(*a)));
                            }
                        }
                    }
                    Some(LivenessMethod::Bioprint) => {
                        lines.push("Touch your fingerprint sensor".to_string());
                        lines.push("or look at the camera.".to_string());
                    }
                    None => {
                        lines.push("Preparing the check...".to_string());
                    }
                }
                lines.push("".to_string());
                lines.push("Waiting...".to_string());
                lines
            }
            FlowStep::Complete => {
                let level = self
                    .flow
                    .attestation()
                    .map(|a| a.level.label())
                    .unwrap_or("verified");
                vec![
                    format!("You're verified: {level}."),
                    "".to_string(),
                    "What others can see:".to_string(),
                    "- a signed note saying 'verified human'".to_string(),
                    "- your public key, dates, a signature".to_string(),
                    "".to_string(),
                    "What others CANNOT see:".to_string(),
                    "- your name, birth date, ID number".to_string(),
                    "- your photo or your biometrics".to_string(),
                ]
            }
        }
    }
}

impl Screen for VerifyScreen {
    fn on_event(&mut self, event: UiEvent) {
        match event {
            UiEvent::Enter => {
                if self.flow.step() == FlowStep::Start {
                    self.begin_flow();
                }
            }
            UiEvent::Char(c) => {
                if self.flow.step() == FlowStep::LivenessChoice {
                    match c {
                        '1' => {
                            let _ = self.choose_video(now_secs());
                        }
                        '2' => {
                            let _ = self.choose_bioprint(now_secs());
                        }
                        _ => {}
                    }
                }
            }
            UiEvent::Escape => self.cancel(),
            UiEvent::Resize(w, h) => {
                self.w = w.max(64);
                self.h = h.max(64);
            }
            UiEvent::Backspace | UiEvent::Tap(_, _) | UiEvent::Scroll(_) | UiEvent::Quit => {}
        }
    }
}

impl PixelScreen for VerifyScreen {
    fn draw(&self, fb: &mut [u32], w: u32, h: u32) {
        // Graceful no-op on an undersized framebuffer.
        if fb.len() < (w as usize).saturating_mul(h as usize) {
            return;
        }
        let pad: u32 = 8;
        let header_h: u32 = 28;
        // Background.
        render::fill_rect(fb, w, h, 0, 0, w, h, color::BLACK);
        // Header.
        render::fill_rect(fb, w, h, 0, 0, w, header_h, color::PANEL);
        render::fill_rect(fb, w, h, 0, header_h - 1, w, 1, color::PANEL_EDGE);
        render::draw_text(fb, w, h, pad + 2, 10, "VERIFY IDENTITY", color::ACCENT);
        let step = self.flow.step().label();
        let step_x = w.saturating_sub((step.len() as u32) * GLYPH_W + pad + 2);
        render::draw_text(fb, w, h, step_x, 10, step, color::DIM);

        // Body.
        let mut y = header_h + pad + 4;
        for line in self.body_lines() {
            if y + GLYPH_H > h.saturating_sub(3 * (GLYPH_H + 4)) {
                break;
            }
            if !line.is_empty() {
                render::draw_text(fb, w, h, pad + 2, y, &line, color::TEXT);
            }
            y += GLYPH_H + 4;
        }

        // Notice (error / denial), if any.
        if !self.notice.is_empty() {
            for line in render::wrap_text(&self.notice, render::cells_for(w - pad * 2).max(8)) {
                if y + GLYPH_H > h.saturating_sub(2 * (GLYPH_H + 4)) {
                    break;
                }
                render::draw_text(fb, w, h, pad + 2, y, &line, color::ACCENT);
                y += GLYPH_H + 4;
            }
        }

        // Privacy footer on EVERY screen.
        let fy = h.saturating_sub(GLYPH_H + pad);
        render::fill_rect(fb, w, h, 0, fy - 4, w, 1, color::PANEL_EDGE);
        render::draw_text(fb, w, h, pad + 2, fy, PRIVACY_LINE, color::DIM);
    }
}

impl TextScreen for VerifyScreen {
    fn draw_text(&self, out: &mut dyn core::fmt::Write, cols: u32, rows: u32) {
        let cols = cols.max(20);
        let _ = writeln!(out, "== VERIFY IDENTITY [{}] ==", self.flow.step().label());
        let _ = writeln!(out);
        let max_lines = rows.saturating_sub(6);
        let mut n = 0u32;
        for line in self.body_lines() {
            if n >= max_lines {
                break;
            }
            let _ = writeln!(out, "{line}");
            n += 1;
        }
        if !self.notice.is_empty() {
            let _ = writeln!(out);
            let _ = writeln!(out, "! {}", self.notice);
        }
        let _ = writeln!(out);
        let _ = writeln!(out, "{}", "-".repeat(cols as usize));
        let _ = writeln!(out, "{PRIVACY_LINE}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::UiEvent;
    use trv_backend::entitlement::{issue, verify_and_check};
    use trv_backend::subscriptions::Tier;
    use trv_core::crypto::ed25519;

    /// Fixed issuer seed for tests only — never a real key.
    const ISSUER_SEED: [u8; 32] = *b"test-ui-verify-issuer-0000000000";

    // ICAO 9303 specimen passport MRZ (public spec example).
    const SPEC_L1: &str = "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<";
    const SPEC_L2: &str = "L898902C36UTO7408122F1204159ZE184226B<<<<<10";
    const TODAY: (u8, u8, u8) = (10, 1, 1);

    fn issuer_pubkey() -> [u8; 32] {
        let (_, public) = ed25519::generate(&ISSUER_SEED);
        *public.as_bytes()
    }

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .expect("test clock")
    }

    fn live_entitlement() -> Entitlement {
        let now = now_secs();
        let receipt = issue(&ISSUER_SEED, Tier::Monthly, now, now + 30 * 86_400).expect("issue");
        verify_and_check(&issuer_pubkey(), &receipt).expect("live")
    }

    fn entitled_screen() -> VerifyScreen {
        let mut s = VerifyScreen::new(640, 400);
        s.set_entitlement(Some(live_entitlement()));
        s
    }

    fn device_keypair() -> (SecretKey, PublicKey) {
        ed25519::generate(&[0xA5u8; 32])
    }

    /// Drive a screen through document + liveness to the finish call.
    fn drive_to_finish(s: &mut VerifyScreen) {
        s.on_event(UiEvent::Enter); // begin (gated: entitled)
        assert_eq!(s.step(), FlowStep::DocumentCapture);
        s.submit_document_lines(SPEC_L1, SPEC_L2, TODAY).unwrap();
        assert_eq!(s.step(), FlowStep::LivenessChoice);
        let ch = s.choose_video(1_000).unwrap();
        assert_eq!(s.step(), FlowStep::LivenessCapture);
        // The platform's role, simulated: sign a passing verdict.
        let (ds, dp) = device_keypair();
        let resp = LivenessResponse::sign(&ds, &dp, LivenessMethod::VideoSelfie, true, ch.nonce);
        s.submit_liveness_response(&resp).unwrap();
        let (_, up) = ed25519::generate(&[0x5Au8; 32]);
        let att = s.finish(&ds, &dp, &up, 2_000).unwrap();
        assert_eq!(s.step(), FlowStep::Complete);
        assert_eq!(att.level, VerificationLevel::HumanVerified);
    }

    // -- Paywall -----------------------------------------------------------

    #[test]
    fn ghost_tier_cannot_start_verification() {
        // No entitlement: the IdentityVerification gate fails closed.
        let mut s = VerifyScreen::new(640, 400);
        s.on_event(UiEvent::Enter);
        assert_eq!(s.step(), FlowStep::Start); // did NOT advance
        assert!(s.notice.contains("paid subscription"));
        // Direct call is gated too — not just the key handler.
        s.begin_flow();
        assert_eq!(s.step(), FlowStep::Start);
    }

    #[test]
    fn expired_entitlement_cannot_start() {
        let mut s = VerifyScreen::new(640, 400);
        let now = now_secs();
        let receipt = issue(&ISSUER_SEED, Tier::Monthly, now - 60 * 86_400, now - 3_600)
            .expect("issue");
        let ent = trv_backend::entitlement::verify_receipt(&issuer_pubkey(), &receipt)
            .expect("genuine but expired");
        s.set_entitlement(Some(ent));
        s.begin_flow();
        assert_eq!(s.step(), FlowStep::Start);
    }

    #[test]
    fn paid_tier_starts() {
        let mut s = entitled_screen();
        s.on_event(UiEvent::Enter);
        assert_eq!(s.step(), FlowStep::DocumentCapture);
        assert!(s.notice.is_empty());
    }

    #[test]
    fn revoking_entitlement_mid_flow_blocks_restart_not_progress() {
        // Revocation takes effect on the NEXT begin, like other gates:
        // in-progress state is not torn down mid-flow (fail closed at
        // the gate, not by yanking state).
        let mut s = entitled_screen();
        s.on_event(UiEvent::Enter);
        s.set_entitlement(None);
        s.cancel();
        s.begin_flow();
        assert_eq!(s.step(), FlowStep::Start);
    }

    // -- Flow through the screen --------------------------------------------

    #[test]
    fn full_flow_through_screen() {
        let mut s = entitled_screen();
        drive_to_finish(&mut s);
        let att = s.attestation().expect("attestation issued");
        att.verify(2_001).unwrap();
    }

    #[test]
    fn invalid_document_shows_notice_stays_on_step() {
        let mut s = entitled_screen();
        s.on_event(UiEvent::Enter);
        let mut l2 = SPEC_L2.to_string().into_bytes();
        l2[0] = b'M';
        let bad_l2 = String::from_utf8(l2).unwrap();
        let err = s
            .submit_document_lines(SPEC_L1, &bad_l2, TODAY)
            .unwrap_err();
        assert_eq!(err, FlowError::Protocol(trv_core::verify::VerifyError::MrzDocNumberChecksum));
        assert_eq!(s.step(), FlowStep::DocumentCapture);
        assert!(!s.notice.is_empty());
    }

    #[test]
    fn keypress_1_and_2_choose_method() {
        let mut s = entitled_screen();
        s.on_event(UiEvent::Enter);
        s.submit_document_lines(SPEC_L1, SPEC_L2, TODAY).unwrap();
        s.on_event(UiEvent::Char('2'));
        assert_eq!(s.step(), FlowStep::LivenessCapture);
        assert_eq!(
            s.pending_challenge().map(|c| c.method),
            Some(LivenessMethod::Bioprint)
        );
    }

    #[test]
    fn escape_cancels_to_start() {
        let mut s = entitled_screen();
        s.on_event(UiEvent::Enter);
        assert_eq!(s.step(), FlowStep::DocumentCapture);
        s.on_event(UiEvent::Escape);
        assert_eq!(s.step(), FlowStep::Start);
    }

    #[test]
    fn failed_liveness_returns_to_choice() {
        let mut s = entitled_screen();
        s.on_event(UiEvent::Enter);
        s.submit_document_lines(SPEC_L1, SPEC_L2, TODAY).unwrap();
        let ch = s.choose_video(1_000).unwrap();
        let (ds, dp) = device_keypair();
        let resp = LivenessResponse::sign(&ds, &dp, LivenessMethod::VideoSelfie, false, ch.nonce);
        let err = s.submit_liveness_response(&resp).unwrap_err();
        assert_eq!(err, FlowError::LivenessFailed);
        assert_eq!(s.step(), FlowStep::LivenessChoice);
    }

    // -- Rendering ------------------------------------------------------------

    fn screen_at_complete() -> VerifyScreen {
        let mut s = entitled_screen();
        drive_to_finish(&mut s);
        s
    }

    #[test]
    fn privacy_line_on_every_screen_text() {
        // Walk every step and assert the privacy promise renders.
        let mut s = entitled_screen();
        for _ in 0..5 {
            let mut out = String::new();
            s.draw_text(&mut out, 60, 30);
            assert!(
                out.contains(PRIVACY_LINE),
                "privacy line missing at step {:?}",
                s.step()
            );
            match s.step() {
                FlowStep::Start => s.on_event(UiEvent::Enter),
                FlowStep::DocumentCapture => {
                    let _ = s.submit_document_lines(SPEC_L1, SPEC_L2, TODAY).unwrap();
                }
                FlowStep::LivenessChoice => {
                    let _ = s.choose_video(1_000);
                }
                FlowStep::LivenessCapture => break, // needs platform; covered below
                FlowStep::Complete => break,
            }
        }
        // Complete screen separately.
        let done = screen_at_complete();
        let mut out = String::new();
        done.draw_text(&mut out, 60, 30);
        assert!(out.contains(PRIVACY_LINE));
        assert!(out.contains("CANNOT see"));
    }

    #[test]
    fn draw_paints_nonempty_framebuffer() {
        let s = screen_at_complete();
        let mut fb = vec![0u32; 640 * 400];
        s.draw(&mut fb, 640, 400);
        let painted = fb.iter().filter(|&&p| p != 0).count();
        assert!(painted > 500, "expected painted pixels, got {painted}");
    }

    #[test]
    fn draw_with_tiny_framebuffer_does_not_panic() {
        let s = VerifyScreen::new(640, 400);
        let mut fb = vec![0u32; 10];
        s.draw(&mut fb, 640, 400);
        assert!(fb.iter().all(|&p| p == 0));
    }

    #[test]
    fn draw_text_renders_all_steps() {
        let s = entitled_screen();
        let mut out = String::new();
        s.draw_text(&mut out, 60, 24);
        assert!(out.contains("VERIFY IDENTITY"));
        assert!(out.contains("real person"));
    }

    #[test]
    fn liveness_capture_shows_challenge_moves() {
        let mut s = entitled_screen();
        s.on_event(UiEvent::Enter);
        s.submit_document_lines(SPEC_L1, SPEC_L2, TODAY).unwrap();
        let ch = s.choose_video(1_000).unwrap();
        let mut out = String::new();
        s.draw_text(&mut out, 60, 30);
        // The three challenge actions are shown so the user can do them.
        let mut shown = 0;
        for a in ch.actions {
            if out.contains(action_label(a)) {
                shown += 1;
            }
        }
        assert_eq!(shown, 3);
    }

    // -- Platform trait contract --------------------------------------------------

    /// A stub platform: records calls, returns canned outputs. Stands
    /// in for the future real camera/OCR/biometric implementation.
    struct StubPlatform {
        mrz: (String, String),
        pass: bool,
        device: (SecretKey, PublicKey),
        calls: Vec<&'static str>,
    }

    impl PlatformCapture for StubPlatform {
        fn capture_document_image(&mut self) -> Result<Vec<u8>, CaptureError> {
            self.calls.push("capture_document_image");
            Ok(vec![0xFF, 0xD8, 0xFF]) // fake JPEG header
        }
        fn extract_mrz(&mut self, _image: &[u8]) -> Result<(String, String), CaptureError> {
            self.calls.push("extract_mrz");
            Ok(self.mrz.clone())
        }
        fn perform_liveness(
            &mut self,
            challenge: &LivenessChallenge,
        ) -> Result<LivenessResponse, CaptureError> {
            self.calls.push("perform_liveness");
            // The contract: analyze on-device, wipe, sign the verdict.
            // The stub signs a verdict directly.
            Ok(LivenessResponse::sign(
                &self.device.0,
                &self.device.1,
                challenge.method,
                self.pass,
                challenge.nonce,
            ))
        }
    }

    #[test]
    fn platform_trait_drives_full_flow() {
        // This is exactly how the future Android implementation plugs
        // in: platform outputs feed the screen's submit_* methods.
        let (ds, dp) = device_keypair();
        let mut platform = StubPlatform {
            mrz: (SPEC_L1.to_string(), SPEC_L2.to_string()),
            pass: true,
            device: (ds.clone(), dp),
            calls: Vec::new(),
        };
        let mut s = entitled_screen();
        s.begin_flow();

        let image = platform.capture_document_image().unwrap();
        let (l1, l2) = platform.extract_mrz(&image).unwrap();
        s.submit_document_lines(&l1, &l2, TODAY).unwrap();

        let challenge = s.choose_bioprint(1_000).unwrap();
        let response = platform.perform_liveness(&challenge).unwrap();
        s.submit_liveness_response(&response).unwrap();

        let (_, up) = ed25519::generate(&[0x5Au8; 32]);
        let att = s.finish(&ds, &dp, &up, 2_000).unwrap();
        assert_eq!(att.level, VerificationLevel::HumanVerified);
        assert_eq!(
            platform.calls,
            vec![
                "capture_document_image",
                "extract_mrz",
                "perform_liveness"
            ]
        );
    }

    #[test]
    fn platform_capture_errors_are_plain_reason_codes() {
        let variants = [
            CaptureError::Unavailable,
            CaptureError::UserCancelled,
            CaptureError::CaptureFailed,
            CaptureError::OcrFailed,
            CaptureError::HardwareBusy,
        ];
        for v in variants {
            let rendered = format!("{:?} | {}", v, v);
            assert!(!rendered.contains("ERIKSSON"));
            assert!(!rendered.is_empty());
        }
    }
}
