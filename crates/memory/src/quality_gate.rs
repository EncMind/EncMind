use encmind_core::error::MemoryError;
use encmind_core::types::{CitationScore, GoldenExample};

/// Result of a retrieval quality evaluation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EvalResult {
    pub total_queries: usize,
    pub precision: f32,
    pub recall: f32,
    pub per_query: Vec<QueryEvalResult>,
    pub passed: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct QueryEvalResult {
    pub query: String,
    pub precision: f32,
    pub recall: f32,
}

/// Gate that blocks operations if retrieval quality drops below thresholds.
pub struct RetrievalQualityGate {
    eval_set: Vec<GoldenExample>,
    min_precision: f32,
    min_citation_score: f32,
    enabled: bool,
}

impl RetrievalQualityGate {
    pub fn new(min_precision: f32, min_citation_score: f32) -> Self {
        Self {
            eval_set: Vec::new(),
            min_precision,
            min_citation_score,
            enabled: true,
        }
    }

    pub fn disabled() -> Self {
        Self {
            eval_set: Vec::new(),
            min_precision: 0.0,
            min_citation_score: 0.0,
            enabled: false,
        }
    }

    /// Load evaluation set from a JSON file.
    pub fn load_eval_set(&mut self, path: &std::path::Path) -> Result<(), MemoryError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| MemoryError::InvalidConfig(format!("failed to read eval set: {e}")))?;
        let examples: Vec<GoldenExample> = serde_json::from_str(&content)
            .map_err(|e| MemoryError::InvalidConfig(format!("failed to parse eval set: {e}")))?;
        self.eval_set = examples;
        Ok(())
    }

    /// Set the evaluation set directly (useful for tests).
    pub fn set_eval_set(&mut self, examples: Vec<GoldenExample>) {
        self.eval_set = examples;
    }

    /// Return the number of examples in the evaluation set.
    pub fn eval_set_len(&self) -> usize {
        self.eval_set.len()
    }

    /// Evaluate retrieval quality against the golden set.
    ///
    /// `search_fn` is called for each query and returns the retrieved memory IDs.
    pub fn evaluate(
        &self,
        search_results: &[(String, Vec<String>)], // (query, retrieved_ids)
    ) -> EvalResult {
        if self.eval_set.is_empty() || !self.enabled {
            return EvalResult {
                total_queries: 0,
                precision: 1.0,
                recall: 1.0,
                per_query: Vec::new(),
                passed: true,
            };
        }

        let mut total_precision = 0.0;
        let mut total_recall = 0.0;
        let mut per_query = Vec::new();

        for example in &self.eval_set {
            let retrieved_ids = search_results
                .iter()
                .find(|(query, _)| query == &example.query)
                .map(|(_, ids)| ids.as_slice())
                .unwrap_or(&[]);

            let expected_set: std::collections::HashSet<&str> = example
                .expected_memory_ids
                .iter()
                .map(|s| s.as_str())
                .collect();
            let unexpected_set: std::collections::HashSet<&str> = example
                .expected_not_ids
                .iter()
                .map(|s| s.as_str())
                .collect();
            let retrieved_set: std::collections::HashSet<&str> =
                retrieved_ids.iter().map(|s| s.as_str()).collect();

            // Precision: fraction of retrieved that are expected (and not unexpected)
            let relevant_retrieved = retrieved_set
                .iter()
                .filter(|id| expected_set.contains(*id) && !unexpected_set.contains(*id))
                .count();
            let precision = if retrieved_set.is_empty() {
                0.0
            } else {
                relevant_retrieved as f32 / retrieved_set.len() as f32
            };

            // Recall: fraction of expected that were retrieved
            let recall = if expected_set.is_empty() {
                1.0
            } else {
                relevant_retrieved as f32 / expected_set.len() as f32
            };

            total_precision += precision;
            total_recall += recall;
            per_query.push(QueryEvalResult {
                query: example.query.clone(),
                precision,
                recall,
            });
        }

        let n = self.eval_set.len() as f32;
        let avg_precision = if n > 0.0 { total_precision / n } else { 0.0 };
        let avg_recall = if n > 0.0 { total_recall / n } else { 0.0 };

        EvalResult {
            total_queries: self.eval_set.len(),
            precision: avg_precision,
            recall: avg_recall,
            per_query,
            passed: avg_precision >= self.min_precision,
        }
    }

    /// Check whether a citation score meets the quality threshold.
    pub fn check_citation_quality(&self, score: &CitationScore) -> bool {
        if !self.enabled {
            return true;
        }
        score.relevance >= self.min_citation_score
    }

    /// Regression gate: returns true if quality is above threshold.
    pub fn regression_gate(&self, eval_result: &EvalResult) -> bool {
        if !self.enabled {
            return true;
        }
        eval_result.passed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use encmind_core::types::MemoryId;

    fn make_eval_set() -> Vec<GoldenExample> {
        vec![
            GoldenExample {
                query: "dark mode".into(),
                expected_memory_ids: vec!["mem-1".into(), "mem-2".into()],
                expected_not_ids: vec![],
            },
            GoldenExample {
                query: "meeting schedule".into(),
                expected_memory_ids: vec!["mem-3".into()],
                expected_not_ids: vec!["mem-4".into()],
            },
        ]
    }

    #[test]
    fn perfect_retrieval() {
        let mut gate = RetrievalQualityGate::new(0.5, 0.7);
        gate.set_eval_set(make_eval_set());

        let results = vec![
            ("dark mode".into(), vec!["mem-1".into(), "mem-2".into()]),
            ("meeting schedule".into(), vec!["mem-3".into()]),
        ];

        let eval = gate.evaluate(&results);
        assert_eq!(eval.total_queries, 2);
        assert!((eval.precision - 1.0).abs() < 0.001);
        assert!((eval.recall - 1.0).abs() < 0.001);
        assert!(eval.passed);
    }

    #[test]
    fn no_retrieval() {
        let mut gate = RetrievalQualityGate::new(0.5, 0.7);
        gate.set_eval_set(make_eval_set());

        let results = vec![
            ("dark mode".into(), vec![]),
            ("meeting schedule".into(), vec![]),
        ];

        let eval = gate.evaluate(&results);
        assert!((eval.precision - 0.0).abs() < 0.001);
        assert!((eval.recall - 0.0).abs() < 0.001);
        assert!(!eval.passed);
    }

    #[test]
    fn partial_retrieval() {
        let mut gate = RetrievalQualityGate::new(0.3, 0.7);
        gate.set_eval_set(make_eval_set());

        let results = vec![
            ("dark mode".into(), vec!["mem-1".into()]), // 1/2 expected
            ("meeting schedule".into(), vec!["mem-3".into()]),
        ];

        let eval = gate.evaluate(&results);
        assert!(eval.precision > 0.0);
        assert!(eval.recall > 0.0);
    }

    #[test]
    fn missing_eval_queries_are_penalized() {
        let mut gate = RetrievalQualityGate::new(0.6, 0.7);
        gate.set_eval_set(make_eval_set());

        // Only one query result provided for a two-query eval set.
        let results = vec![("dark mode".into(), vec!["mem-1".into(), "mem-2".into()])];

        let eval = gate.evaluate(&results);
        assert_eq!(eval.total_queries, 2);
        assert!(eval.precision < 1.0);
        assert!(eval.recall < 1.0);
        assert!(!eval.passed);
    }

    #[test]
    fn unexpected_reduces_precision() {
        let mut gate = RetrievalQualityGate::new(0.9, 0.7);
        gate.set_eval_set(make_eval_set());

        let results = vec![
            (
                "dark mode".into(),
                vec!["mem-1".into(), "mem-2".into(), "mem-99".into()],
            ), // extra result
            ("meeting schedule".into(), vec!["mem-3".into()]),
        ];

        let eval = gate.evaluate(&results);
        // First query: 2/3 precision, second: 1/1
        assert!(eval.precision < 1.0);
    }

    #[test]
    fn gate_passes_above_threshold() {
        let gate = RetrievalQualityGate::new(0.5, 0.7);
        let eval = EvalResult {
            total_queries: 1,
            precision: 0.8,
            recall: 0.8,
            per_query: vec![],
            passed: true,
        };
        assert!(gate.regression_gate(&eval));
    }

    #[test]
    fn gate_fails_below_threshold() {
        let gate = RetrievalQualityGate::new(0.5, 0.7);
        let eval = EvalResult {
            total_queries: 1,
            precision: 0.3,
            recall: 0.3,
            per_query: vec![],
            passed: false,
        };
        assert!(!gate.regression_gate(&eval));
    }

    #[test]
    fn disabled_always_passes() {
        let gate = RetrievalQualityGate::disabled();
        let eval = EvalResult {
            total_queries: 0,
            precision: 0.0,
            recall: 0.0,
            per_query: vec![],
            passed: false,
        };
        assert!(gate.regression_gate(&eval));
    }

    #[test]
    fn empty_eval_set_passes() {
        let gate = RetrievalQualityGate::new(0.5, 0.7);
        let eval = gate.evaluate(&[]);
        assert!(eval.passed);
    }

    #[test]
    fn citation_high_passes() {
        let gate = RetrievalQualityGate::new(0.5, 0.7);
        let score = CitationScore {
            memory_id: MemoryId::new(),
            relevance: 0.9,
            faithfulness: 0.95,
        };
        assert!(gate.check_citation_quality(&score));
    }

    #[test]
    fn citation_low_fails() {
        let gate = RetrievalQualityGate::new(0.5, 0.7);
        let score = CitationScore {
            memory_id: MemoryId::new(),
            relevance: 0.3,
            faithfulness: 0.95,
        };
        assert!(!gate.check_citation_quality(&score));
    }

    #[test]
    fn load_eval_set_from_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("eval.json");
        let data = serde_json::to_string(&make_eval_set()).unwrap();
        std::fs::write(&path, data).unwrap();

        let mut gate = RetrievalQualityGate::new(0.5, 0.7);
        gate.load_eval_set(&path).unwrap();
        assert_eq!(gate.eval_set.len(), 2);
    }

    #[test]
    fn eval_result_serde() {
        let result = EvalResult {
            total_queries: 2,
            precision: 0.85,
            recall: 0.90,
            per_query: vec![],
            passed: true,
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: EvalResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.total_queries, 2);
        assert!(back.passed);
    }
}
