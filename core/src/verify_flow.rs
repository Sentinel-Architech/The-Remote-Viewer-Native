//! User-facing ID verification flow: a step-by-step state machine.
//!
//! Pure Rust, std-only. This module walks a user through on-device
//! verification — document check, then liveness — and ends with a
//! signed attestation. It builds on the [`crate::verify`] protocol.
//!
//! ## Privacy guarantee (hard)
//!
//! Verifiable personal information NEVER ends up in a stranger's hands,
//! because it never leaves the device at all:
//!
//! - [`VerificationFlow::submit_document`] takes the MRZ lines, runs the
//!   check, and drops them the moment the function returns. The flow
//!   keeps only a pass/fail flag — no document number, no birth date,
//!   no name. There is no field on this struct that could hold them.
//! - [`VerificationFlow::submit_liveness`] takes the platform's *signed
//!   verdict* ([`LivenessResponse`]) and runs it through the
//!   challenge session: replay rejected, method binding enforced,
//!   device signature checked. Video frames and biometric templates
//!   were captured, analyzed, and wiped by the platform layer before
//!   this function was ever called. The flow keeps only the verified
//!   verdict fields — never raw capture data.
//! - [`VerificationFlow::complete`] builds the [`ProofOfLife`] record
//!   (method code, verdict, nonce, timestamp, signature) and issues
//!   the [`VerificationAttestation`] — the ONLY artifact that may
//!   leave the device. The attestation carries the subject's public
//!   key, a verification level code, timestamps, and a device
//!   signature. Zero personal data.
//! - This module performs no I/O at all. No network, no camera, no
//!   logging of personal data.
//!
//! ## Steps
//!
//! ```text
//! Start → DocumentCapture → LivenessChoice → LivenessCapture → Complete
//! ```
//!
//! (The MRZ *check* runs inside [`VerificationFlow::submit_document`];
//! a passing check advances straight to `LivenessChoice`.)
//!
//! Every transition validates its inputs fail-closed. Steps cannot be
//! skipped: calling a step out of order returns
//! [`FlowError::WrongStep`]. A failed liveness verdict returns
//! [`FlowError::LivenessFailed`] and resets to `LivenessChoice` so a
//! fresh challenge must be issued for any retry.
//!
//! NOT externally audited — like the rest of `trv_core`, this module is
//! hand-written and has not had an independent cryptographic or
//! biometric-security audit. Do not rely on it for production identity
//! decisions until that audit happens.

use crate::crypto::ed25519::{PublicKey, SecretKey};
use crate::verify::{
    check_mrz, LivenessChallenge, LivenessMethod, LivenessResponse, LivenessSession, LivenessVerdict,
    ProofOfLife, VerificationAttestation, VerificationLevel, VerifyError,
};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Every failure the verification flow can report.
///
/// Variants carry NO data — only reason codes — so an error can never
/// echo back MRZ lines, names, or any other personal information.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowError {
    /// A step was called out of order (e.g. liveness before document).
    WrongStep,
    /// The flow already completed; it cannot run twice.
    AlreadyComplete,
    /// The platform's liveness verdict was "fail". The flow resets to
    /// the liveness-choice step so a retry needs a fresh challenge.
    LivenessFailed,
    /// No attestation exists yet — the flow is not complete.
    NoAttestation,
    /// An underlying protocol check failed (MRZ, challenge, signature…).
    Protocol(VerifyError),
    /// The device key offered at completion differs from the device key
    /// that signed the liveness response. The liveness check, the proof,
    /// and the attestation must all belong to the same phone — mixing
    /// devices fails closed.
    DeviceMismatch,
}

impl std::fmt::Display for FlowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            FlowError::WrongStep => "verification step out of order",
            FlowError::AlreadyComplete => "verification already complete",
            FlowError::LivenessFailed => "liveness check did not pass",
            FlowError::NoAttestation => "no attestation issued yet",
            FlowError::DeviceMismatch => "device key does not match the liveness check",
            FlowError::Protocol(e) => return write!(f, "verification failed: {e}"),
        };
        f.write_str(s)
    }
}

impl std::error::Error for FlowError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            FlowError::Protocol(e) => Some(e),
            _ => None,
        }
    }
}

impl From<VerifyError> for FlowError {
    fn from(e: VerifyError) -> Self {
        FlowError::Protocol(e)
    }
}

// ---------------------------------------------------------------------------
// Flow steps
// ---------------------------------------------------------------------------

/// Where the user is in the verification flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowStep {
    /// Not started.
    Start,
    /// Waiting for the ID document's MRZ lines (from platform OCR).
    DocumentCapture,
    /// Waiting for the user to pick video selfie or bioprint.
    LivenessChoice,
    /// Challenge issued; waiting for the platform's signed verdict.
    LivenessCapture,
    /// Attestation issued. Terminal.
    Complete,
}

impl FlowStep {
    /// Plain-language label for UI screens.
    pub fn label(self) -> &'static str {
        match self {
            FlowStep::Start => "start",
            FlowStep::DocumentCapture => "scan your ID",
            FlowStep::LivenessChoice => "choose liveness check",
            FlowStep::LivenessCapture => "liveness check",
            FlowStep::Complete => "verified",
        }
    }
}

// ---------------------------------------------------------------------------
// The flow
// ---------------------------------------------------------------------------

/// Step-by-step on-device ID verification.
///
/// Owns the liveness session, the current step, and — on success — the
/// proof of life and the attestation. It deliberately owns NO personal
/// data: no MRZ lines, no document image, no video, no biometrics.
pub struct VerificationFlow {
    step: FlowStep,
    session: LivenessSession,
    /// The liveness method the user chose (set in `LivenessChoice`).
    method: Option<LivenessMethod>,
    /// The live challenge awaiting a platform verdict.
    challenge: Option<LivenessChallenge>,
    /// The platform's signed verdict, after the session verified it
    /// (replay-checked, method-bound, signature-checked).
    verified_response: Option<LivenessResponse>,
    /// The signed liveness record (built at completion, when the
    /// device secret is transiently available for the one signature).
    proof: Option<ProofOfLife>,
    /// The issued attestation (set at `Complete`).
    attestation: Option<VerificationAttestation>,
}

impl VerificationFlow {
    /// A fresh flow at [`FlowStep::Start`].
    pub fn new() -> Self {
        VerificationFlow {
            step: FlowStep::Start,
            session: LivenessSession::new(),
            method: None,
            challenge: None,
            verified_response: None,
            proof: None,
            attestation: None,
        }
    }

    /// Reset back to [`FlowStep::Start`], discarding all progress.
    /// Used when the user cancels mid-flow.
    pub fn reset(&mut self) {
        *self = VerificationFlow::new();
    }

    /// Current step.
    pub fn step(&self) -> FlowStep {
        self.step
    }

    /// `Start` → `DocumentCapture`. The user is ready to scan their ID.
    pub fn begin(&mut self) -> Result<(), FlowError> {
        match self.step {
            FlowStep::Start => {
                self.step = FlowStep::DocumentCapture;
                Ok(())
            }
            FlowStep::Complete => Err(FlowError::AlreadyComplete),
            _ => Err(FlowError::WrongStep),
        }
    }

    /// Run the MRZ document check.
    ///
    /// `DocumentCapture` → `LivenessChoice` on success.
    ///
    /// Privacy: `line1`/`line2` are validated and then dropped when
    /// this function returns. Nothing from the document — not the
    /// number, not the birth date, not the name — is stored. Only the
    /// pass/fail outcome advances the flow.
    pub fn submit_document(
        &mut self,
        line1: &str,
        line2: &str,
        today: (u8, u8, u8),
    ) -> Result<VerificationLevel, FlowError> {
        if self.step == FlowStep::Complete {
            return Err(FlowError::AlreadyComplete);
        }
        if self.step != FlowStep::DocumentCapture {
            return Err(FlowError::WrongStep);
        }
        // The MRZ lines live only as long as this call. `check_mrz`
        // returns the extracted document facts; we keep none of them —
        // only the knowledge that the check passed.
        check_mrz(line1, line2, today)?;
        self.step = FlowStep::LivenessChoice;
        Ok(VerificationLevel::DocumentChecked)
    }

    /// The user picks a liveness method.
    ///
    /// `LivenessChoice` → `LivenessCapture`. Issues a fresh challenge
    /// bound to the chosen method and returns it — the embedding app
    /// hands it to the platform capture layer.
    pub fn choose_liveness(
        &mut self,
        method: LivenessMethod,
        issued_at: u64,
    ) -> Result<LivenessChallenge, FlowError> {
        if self.step == FlowStep::Complete {
            return Err(FlowError::AlreadyComplete);
        }
        if self.step != FlowStep::LivenessChoice {
            return Err(FlowError::WrongStep);
        }
        let challenge = self.session.issue_challenge(method, issued_at)?;
        self.method = Some(method);
        self.challenge = Some(challenge);
        self.step = FlowStep::LivenessCapture;
        Ok(challenge)
    }

    /// The live challenge awaiting the platform's verdict, if any.
    ///
    /// The app passes this to its platform capture implementation,
    /// which performs the actual video/biometric capture on-device.
    pub fn pending_challenge(&self) -> Option<LivenessChallenge> {
        self.challenge
    }

    /// Accept the platform's signed liveness verdict.
    ///
    /// `LivenessCapture` → verdict recorded. The response carries only
    /// the verdict — raw video/biometric bytes never reach this
    /// function (the platform analyzed and wiped them first). The
    /// session checks the challenge is live (replay rejected), the
    /// method matches the issued challenge, and the device signature is
    /// valid — all fail closed.
    ///
    /// On a passing verdict the flow holds the verified response and
    /// the app may call [`VerificationFlow::complete`], which builds
    /// the signed [`ProofOfLife`]. On a failing verdict this returns
    /// [`FlowError::LivenessFailed`] and resets to
    /// [`FlowStep::LivenessChoice`]: any retry needs a fresh challenge.
    pub fn submit_liveness(
        &mut self,
        response: &LivenessResponse,
    ) -> Result<LivenessVerdict, FlowError> {
        if self.step == FlowStep::Complete {
            return Err(FlowError::AlreadyComplete);
        }
        if self.step != FlowStep::LivenessCapture {
            return Err(FlowError::WrongStep);
        }
        let verdict = self.session.verify_response(response)?;
        if !verdict.passed {
            // Fail closed: no verdict recorded, challenge consumed, back
            // to the choice step for a fresh challenge on retry.
            self.method = None;
            self.challenge = None;
            self.step = FlowStep::LivenessChoice;
            return Err(FlowError::LivenessFailed);
        }
        self.verified_response = Some(*response);
        Ok(verdict)
    }

    /// Issue the signed proof of life and attestation, finishing the flow.
    ///
    /// Requires a passing, session-verified liveness response. Builds
    /// the [`ProofOfLife`] with the device key — which must be the SAME
    /// device key that signed the liveness response ([`FlowError::DeviceMismatch`]
    /// otherwise) — then issues the [`VerificationAttestation`] at
    /// [`VerificationLevel::HumanVerified`].
    ///
    /// The attestation contains the subject's identity key, the level
    /// code, timestamps, and the device signature — zero personal data.
    /// It is the ONLY artifact from the flow that may leave the device.
    ///
    /// The device secret is used transiently for these two signatures
    /// and is never stored.
    pub fn complete(
        &mut self,
        device_secret: &SecretKey,
        device_public: &PublicKey,
        subject_key: &PublicKey,
        issued_at: u64,
    ) -> Result<VerificationAttestation, FlowError> {
        if self.step == FlowStep::Complete {
            return Err(FlowError::AlreadyComplete);
        }
        let response = self.verified_response.ok_or(FlowError::WrongStep)?;
        if device_public != &response.device_key {
            return Err(FlowError::DeviceMismatch);
        }
        let method = self.method.unwrap_or(response.method);
        let proof = ProofOfLife::attest(
            device_secret,
            device_public,
            method,
            true,
            response.nonce,
            issued_at,
        );
        let attestation = VerificationAttestation::issue(
            device_secret,
            device_public,
            subject_key,
            VerificationLevel::HumanVerified,
            issued_at,
        )?;
        self.proof = Some(proof);
        self.attestation = Some(attestation);
        self.step = FlowStep::Complete;
        Ok(attestation)
    }

    /// The signed liveness record, if the flow completed.
    ///
    /// Contains only the method code, the verdict, the nonce, the
    /// timestamp, the device key, and the signature — no video, no
    /// biometrics, structurally nowhere to put them.
    pub fn proof(&self) -> Option<ProofOfLife> {
        self.proof
    }

    /// The issued attestation, if the flow completed.
    pub fn attestation(&self) -> Option<VerificationAttestation> {
        self.attestation
    }
}

impl Default for VerificationFlow {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ed25519;

    // ICAO 9303 specimen passport MRZ (public spec example).
    const SPEC_L1: &str = "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<";
    const SPEC_L2: &str = "L898902C36UTO7408122F1204159ZE184226B<<<<<10";
    /// "Today" before the specimen's 12-04-15 expiry.
    const TODAY: (u8, u8, u8) = (10, 1, 1);

    fn device_keypair() -> (SecretKey, PublicKey) {
        ed25519::generate(&[0xA5u8; 32])
    }

    fn user_keypair() -> (SecretKey, PublicKey) {
        ed25519::generate(&[0x5Au8; 32])
    }

    /// Drive a flow through document + liveness to the point where
    /// `complete` can be called. Returns the flow and key material.
    fn flow_ready_to_complete(
        method: LivenessMethod,
    ) -> (VerificationFlow, SecretKey, PublicKey, PublicKey) {
        let (ds, dp) = device_keypair();
        let (_, up) = user_keypair();
        let mut flow = VerificationFlow::new();
        flow.begin().unwrap();
        let level = flow.submit_document(SPEC_L1, SPEC_L2, TODAY).unwrap();
        assert_eq!(level, VerificationLevel::DocumentChecked);
        let challenge = flow.choose_liveness(method, 1_000).unwrap();
        assert_eq!(flow.pending_challenge(), Some(challenge));
        // The platform's role, simulated: sign a passing verdict.
        let response =
            LivenessResponse::sign(&ds, &dp, method, true, challenge.nonce);
        flow.submit_liveness(&response).unwrap();
        (flow, ds, dp, up)
    }

    fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
        if needle.is_empty() || needle.len() > haystack.len() {
            return false;
        }
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    // -- Happy path ----------------------------------------------------------

    #[test]
    fn full_flow_video_selfie_issues_human_verified_attestation() {
        let (mut flow, ds, dp, up) =
            flow_ready_to_complete(LivenessMethod::VideoSelfie);
        assert_eq!(flow.step(), FlowStep::LivenessCapture);
        let att = flow.complete(&ds, &dp, &up, 2_000).unwrap();
        assert_eq!(flow.step(), FlowStep::Complete);
        assert_eq!(att.level, VerificationLevel::HumanVerified);
        assert_eq!(att.subject_key, up);
        att.verify(2_001).unwrap();
        assert_eq!(flow.attestation(), Some(att));
        // The proof of life is properly signed: verify() passes.
        let proof = flow.proof().expect("proof recorded at completion");
        assert!(proof.passed);
        assert_eq!(proof.method, LivenessMethod::VideoSelfie);
        proof.verify().unwrap();
    }

    #[test]
    fn full_flow_bioprint_issues_attestation() {
        let (mut flow, ds, dp, up) =
            flow_ready_to_complete(LivenessMethod::Bioprint);
        let att = flow.complete(&ds, &dp, &up, 2_000).unwrap();
        assert_eq!(att.level, VerificationLevel::HumanVerified);
        att.verify(2_001).unwrap();
    }

    #[test]
    fn step_labels_are_plain_language() {        assert_eq!(FlowStep::DocumentCapture.label(), "scan your ID");
        assert_eq!(FlowStep::LivenessChoice.label(), "choose liveness check");
        assert_eq!(FlowStep::Complete.label(), "verified");
    }

    // -- Step ordering --------------------------------------------------------

    #[test]
    fn begin_twice_is_wrong_step() {
        let mut flow = VerificationFlow::new();
        flow.begin().unwrap();
        assert_eq!(flow.begin(), Err(FlowError::WrongStep));
    }

    #[test]
    fn cannot_skip_document_step() {
        let mut flow = VerificationFlow::new();
        // Never called begin(): choosing liveness is out of order.
        assert_eq!(
            flow.choose_liveness(LivenessMethod::VideoSelfie, 1_000),
            Err(FlowError::WrongStep)
        );
        // begin() then jump straight to liveness response: wrong step.
        flow.begin().unwrap();
        let (ds, dp) = device_keypair();
        let resp = LivenessResponse::sign(&ds, &dp, LivenessMethod::VideoSelfie, true, [1u8; 32]);
        assert_eq!(flow.submit_liveness(&resp), Err(FlowError::WrongStep));
    }

    #[test]
    fn cannot_complete_before_liveness() {
        let mut flow = VerificationFlow::new();
        flow.begin().unwrap();
        flow.submit_document(SPEC_L1, SPEC_L2, TODAY).unwrap();
        let (ds, dp) = device_keypair();
        let (_, up) = user_keypair();
        assert_eq!(
            flow.complete(&ds, &dp, &up, 2_000),
            Err(FlowError::WrongStep)
        );
    }

    #[test]
    fn complete_twice_is_already_complete() {
        let (mut flow, ds, dp, up) =
            flow_ready_to_complete(LivenessMethod::VideoSelfie);
        flow.complete(&ds, &dp, &up, 2_000).unwrap();
        assert_eq!(
            flow.complete(&ds, &dp, &up, 2_000),
            Err(FlowError::AlreadyComplete)
        );
        assert_eq!(flow.begin(), Err(FlowError::AlreadyComplete));
    }

    #[test]
    fn reset_returns_to_start() {
        let (mut flow, _, _, _) =
            flow_ready_to_complete(LivenessMethod::VideoSelfie);
        flow.reset();
        assert_eq!(flow.step(), FlowStep::Start);
        assert_eq!(flow.attestation(), None);
        // And the flow is usable again.
        flow.begin().unwrap();
        assert_eq!(flow.step(), FlowStep::DocumentCapture);
    }

    // -- Document failures -----------------------------------------------------

    #[test]
    fn invalid_mrz_rejected_stays_on_document_step() {
        let mut flow = VerificationFlow::new();
        flow.begin().unwrap();
        let mut l2 = SPEC_L2.to_string().into_bytes();
        l2[0] = b'M'; // breaks the document-number check digit
        let bad_l2 = String::from_utf8(l2).unwrap();
        let err = flow.submit_document(SPEC_L1, &bad_l2, TODAY).unwrap_err();
        assert_eq!(err, FlowError::Protocol(VerifyError::MrzDocNumberChecksum));
        // Still on the document step: the user can retry.
        assert_eq!(flow.step(), FlowStep::DocumentCapture);
    }

    #[test]
    fn expired_document_rejected() {
        let mut flow = VerificationFlow::new();
        flow.begin().unwrap();
        // Specimen expired 12-04-15; "today" 26-10-14 is after.
        let err = flow
            .submit_document(SPEC_L1, SPEC_L2, (26, 10, 14))
            .unwrap_err();
        assert_eq!(err, FlowError::Protocol(VerifyError::MrzDocumentExpired));
        assert_eq!(flow.step(), FlowStep::DocumentCapture);
    }

    #[test]
    fn flow_errors_never_echo_personal_data() {
        let variants = [
            FlowError::WrongStep,
            FlowError::AlreadyComplete,
            FlowError::LivenessFailed,
            FlowError::NoAttestation,
            FlowError::DeviceMismatch,
            FlowError::Protocol(VerifyError::MrzDocNumberChecksum),
            FlowError::Protocol(VerifyError::MrzDocumentExpired),
            FlowError::Protocol(VerifyError::LivenessReplayRejected),
        ];
        let needles: &[&[u8]] = &[
            b"ERIKSSON",
            b"ANNA<MARIA",
            b"L898902C3",
            SPEC_L1.as_bytes(),
            SPEC_L2.as_bytes(),
        ];
        for v in variants {
            let rendered = format!("{:?} | {}", v, v);
            for n in needles {
                assert!(
                    !contains_bytes(rendered.as_bytes(), n),
                    "flow error {:?} echoes personal data",
                    v
                );
            }
        }
    }

    // -- Liveness failures -------------------------------------------------------

    #[test]
    fn liveness_replay_rejected() {
        let (ds, dp) = device_keypair();
        let mut flow = VerificationFlow::new();
        flow.begin().unwrap();
        flow.submit_document(SPEC_L1, SPEC_L2, TODAY).unwrap();
        let challenge = flow
            .choose_liveness(LivenessMethod::VideoSelfie, 1_000)
            .unwrap();
        let response =
            LivenessResponse::sign(&ds, &dp, LivenessMethod::VideoSelfie, true, challenge.nonce);
        flow.submit_liveness(&response).unwrap();
        // Same signed response again: the session burned the nonce, so
        // the replay is rejected at the protocol layer — even though
        // the flow step would otherwise accept it.
        assert_eq!(
            flow.submit_liveness(&response),
            Err(FlowError::Protocol(VerifyError::LivenessReplayRejected))
        );
        // The first (legitimate) verdict is untouched.
        assert!(flow.verified_response.is_some());
    }

    #[test]
    fn liveness_method_mismatch_fails_closed() {
        let (ds, dp) = device_keypair();
        let mut flow = VerificationFlow::new();
        flow.begin().unwrap();
        flow.submit_document(SPEC_L1, SPEC_L2, TODAY).unwrap();
        let challenge = flow
            .choose_liveness(LivenessMethod::VideoSelfie, 1_000)
            .unwrap();
        // Platform answers for the wrong method.
        let response =
            LivenessResponse::sign(&ds, &dp, LivenessMethod::Bioprint, true, challenge.nonce);
        assert_eq!(
            flow.submit_liveness(&response),
            Err(FlowError::Protocol(VerifyError::LivenessMethodMismatch))
        );
    }

    #[test]
    fn failed_liveness_verdict_resets_to_choice() {
        let (ds, dp) = device_keypair();
        let mut flow = VerificationFlow::new();
        flow.begin().unwrap();
        flow.submit_document(SPEC_L1, SPEC_L2, TODAY).unwrap();
        let challenge = flow
            .choose_liveness(LivenessMethod::VideoSelfie, 1_000)
            .unwrap();
        // Platform says the check did NOT pass.
        let response =
            LivenessResponse::sign(&ds, &dp, LivenessMethod::VideoSelfie, false, challenge.nonce);
        assert_eq!(
            flow.submit_liveness(&response),
            Err(FlowError::LivenessFailed)
        );
        // Back at the choice step: a retry needs a fresh challenge.
        assert_eq!(flow.step(), FlowStep::LivenessChoice);
        assert_eq!(flow.pending_challenge(), None);
        // And completion is impossible without a passing proof.
        let (_, up) = user_keypair();
        assert_eq!(
            flow.complete(&ds, &dp, &up, 2_000),
            Err(FlowError::WrongStep)
        );
    }

    // -- Attestation privacy -----------------------------------------------------

    #[test]
    fn device_mismatch_at_complete_fails_closed() {
        let (ds, dp) = device_keypair();
        let (es, ep) = ed25519::generate(&[0x77u8; 32]);
        let mut flow = VerificationFlow::new();
        flow.begin().unwrap();
        flow.submit_document(SPEC_L1, SPEC_L2, TODAY).unwrap();
        let challenge = flow
            .choose_liveness(LivenessMethod::VideoSelfie, 1_000)
            .unwrap();
        // Liveness performed and signed by device (ds, dp)...
        let response =
            LivenessResponse::sign(&ds, &dp, LivenessMethod::VideoSelfie, true, challenge.nonce);
        flow.submit_liveness(&response).unwrap();
        // ...but completion offers a DIFFERENT device key.
        let (_, up) = user_keypair();
        assert_eq!(
            flow.complete(&es, &ep, &up, 2_000),
            Err(FlowError::DeviceMismatch)
        );
        assert_eq!(flow.step(), FlowStep::LivenessCapture);
        assert_eq!(flow.attestation(), None);
    }

    #[test]
    fn attestation_bytes_contain_zero_personal_data() {
        let (mut flow, ds, dp, up) =
            flow_ready_to_complete(LivenessMethod::VideoSelfie);
        let att = flow.complete(&ds, &dp, &up, 2_000).unwrap();
        let enc = att.to_bytes();
        let needles: &[&[u8]] = &[
            b"ERIKSSON",
            b"ANNA<MARIA",
            b"L898902C3",
            b"740812",
            b"ZE184226B",
            b"P<UTO",
            SPEC_L1.as_bytes(),
            SPEC_L2.as_bytes(),
        ];
        for n in needles {
            assert!(
                !contains_bytes(&enc, n),
                "attestation leaks personal data"
            );
        }
    }

    #[test]
    fn flow_error_display_is_plain_language() {
        assert_eq!(
            format!("{}", FlowError::WrongStep),
            "verification step out of order"
        );
        assert_eq!(
            format!("{}", FlowError::LivenessFailed),
            "liveness check did not pass"
        );
        assert_eq!(
            format!("{}", FlowError::DeviceMismatch),
            "device key does not match the liveness check"
        );
    }
}
