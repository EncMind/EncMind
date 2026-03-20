/// Reciprocal Rank Fusion (RRF) merges multiple ranked lists.
///
/// Each result gets a score of 1/(k + rank), where k=60 is a standard constant.
/// Results appearing in multiple lists get their scores summed.
pub fn reciprocal_rank_fusion(lists: &[Vec<(String, f32)>], limit: usize) -> Vec<(String, f32)> {
    const K: f32 = 60.0;

    let mut scores: std::collections::HashMap<String, f32> = std::collections::HashMap::new();

    for list in lists {
        for (rank, (id, _original_score)) in list.iter().enumerate() {
            let rrf_score = 1.0 / (K + rank as f32 + 1.0);
            *scores.entry(id.clone()).or_insert(0.0) += rrf_score;
        }
    }

    let mut results: Vec<(String, f32)> = scores.into_iter().collect();
    results.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    results.truncate(limit);
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_list() {
        let list = vec![
            ("a".to_string(), 0.9),
            ("b".to_string(), 0.8),
            ("c".to_string(), 0.7),
        ];
        let results = reciprocal_rank_fusion(&[list], 10);
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].0, "a");
        assert_eq!(results[1].0, "b");
        assert_eq!(results[2].0, "c");
    }

    #[test]
    fn two_lists_merge() {
        let list1 = vec![("a".to_string(), 0.9), ("b".to_string(), 0.8)];
        let list2 = vec![("c".to_string(), 0.9), ("d".to_string(), 0.8)];
        let results = reciprocal_rank_fusion(&[list1, list2], 10);
        assert_eq!(results.len(), 4);
    }

    #[test]
    fn overlap_boost() {
        // "a" appears in both lists at rank 0, so it should get the highest combined score
        let list1 = vec![("a".to_string(), 0.9), ("b".to_string(), 0.8)];
        let list2 = vec![("a".to_string(), 0.95), ("c".to_string(), 0.7)];
        let results = reciprocal_rank_fusion(&[list1, list2], 10);
        assert_eq!(results[0].0, "a", "overlapping entry should rank highest");
        // "a" score should be > any single-list entry
        assert!(results[0].1 > results[1].1);
    }

    #[test]
    fn respects_limit() {
        let list = vec![
            ("a".to_string(), 0.9),
            ("b".to_string(), 0.8),
            ("c".to_string(), 0.7),
            ("d".to_string(), 0.6),
        ];
        let results = reciprocal_rank_fusion(&[list], 2);
        assert_eq!(results.len(), 2);
    }
}
