pub struct ThreatDetector {
    base_threshold: f64,
    confidence_delta: f64,
}

impl ThreatDetector {
    pub fn new(base_threshold: f64) -> Result<Self, &'static str> {
        if !(0.0..=1.0).contains(&base_threshold) {
            return Err("Threshold must be between 0.0 and 1.0.");
        }
        Ok(Self {
            base_threshold,
            confidence_delta: 0.05,
        })
    }

    /// Optional: override the failure probability δ of the statistical bound.
    pub fn with_confidence_delta(mut self, delta: f64) -> Result<Self, &'static str> {
        if !(0.0 < delta && delta < 1.0) {
            return Err("Confidence delta must be strictly between 0 and 1.");
        }
        self.confidence_delta = delta;
        Ok(self)
    }

    /// Two-sided Hoeffding bound: P(|p̂ − p| ≥ ε) ≤ 2·exp(−2nε²)
    /// ⇒ ε = √(ln(2/δ) / 2n). Scales with √(1/n), no variance guess.
    pub fn evaluate_signature(
        &self,
        mismatch_rate: f64,
        matching_bases_count: usize,
    ) -> Result<DetectionResult, &'static str> {
        if !(0.0..=1.0).contains(&mismatch_rate) {
            return Err("Mismatch rate must be between 0.0 and 1.0.");
        }
        if matching_bases_count == 0 {
            return Ok(DetectionResult {
                is_authentic: false,
                mismatch_rate,
                dynamic_threshold: 1.0,
                threat_flagged: true,
                note: "Zero matching bases: complete signal loss or empty transmission.",
            });
        }

        let slack = ((2.0 / self.confidence_delta).ln()
            / (2.0 * matching_bases_count as f64))
            .sqrt();
        let dynamic_threshold = (self.base_threshold + slack).min(1.0);
        let is_authentic = mismatch_rate <= dynamic_threshold;

        Ok(DetectionResult {
            is_authentic,
            mismatch_rate,
            dynamic_threshold,
            threat_flagged: !is_authentic,
            note: "Evaluated with finite-key Hoeffding bound.",
        })
    }
}

#[derive(Debug, Clone)]
pub struct DetectionResult {
    pub is_authentic: bool,
    pub mismatch_rate: f64,
    pub dynamic_threshold: f64,
    pub threat_flagged: bool,
    pub note: &'static str,
}
