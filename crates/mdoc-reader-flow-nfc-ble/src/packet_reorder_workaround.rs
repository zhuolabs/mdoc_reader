use std::collections::HashSet;

pub(crate) fn one_swap_reordered_packets<T: Clone>(packets: &[T]) -> Vec<(usize, Vec<T>)> {
    let mut candidates = Vec::new();
    for swap_at in one_swap_indices(packets.len()) {
        let mut swapped = packets.to_vec();
        swapped.swap(swap_at, swap_at + 1);
        candidates.push((swap_at, swapped));
    }
    candidates
}

pub(crate) fn two_inversion_reordered_packets<T: Clone>(
    packets: &[T],
) -> Vec<(Vec<usize>, Vec<T>)> {
    let packet_len = packets.len();
    if packet_len < 3 {
        return Vec::new();
    }

    let mut seen = HashSet::new();
    let mut candidates = Vec::new();
    for permutation in two_inversion_permutations(packet_len) {
        if seen.insert(permutation.clone()) {
            candidates.push((
                permutation.clone(),
                reorder_by_permutation(packets, &permutation),
            ));
        }
    }
    candidates
}

fn one_swap_indices(packet_len: usize) -> std::ops::Range<usize> {
    0..packet_len.saturating_sub(1)
}

fn reorder_by_permutation<T: Clone>(items: &[T], permutation: &[usize]) -> Vec<T> {
    permutation
        .iter()
        .map(|&index| items[index].clone())
        .collect()
}

fn inversion_count(permutation: &[usize]) -> usize {
    let mut inversions = 0usize;
    for i in 0..permutation.len() {
        for j in (i + 1)..permutation.len() {
            if permutation[i] > permutation[j] {
                inversions += 1;
            }
        }
    }
    inversions
}

fn two_inversion_permutations(packet_len: usize) -> Vec<Vec<usize>> {
    if packet_len < 3 {
        return Vec::new();
    }

    let base: Vec<usize> = (0..packet_len).collect();
    let mut permutations = Vec::new();

    for first_swap in one_swap_indices(packet_len) {
        for second_swap in one_swap_indices(packet_len) {
            if first_swap == second_swap {
                continue;
            }
            let mut permutation = base.clone();
            permutation.swap(first_swap, first_swap + 1);
            permutation.swap(second_swap, second_swap + 1);
            if inversion_count(&permutation) == 2 {
                permutations.push(permutation);
            }
        }
    }
    permutations
}

#[cfg(test)]
mod tests {
    use super::{one_swap_indices, one_swap_reordered_packets, two_inversion_reordered_packets};

    #[test]
    fn one_swap_attempt_count_is_n_minus_1() {
        let packet_len = 4;
        let attempts = one_swap_indices(packet_len).count();
        assert_eq!(attempts, packet_len - 1);
    }

    #[test]
    fn inversion_two_permutation_count_for_n4_is_five() {
        let packets = vec![0, 1, 2, 3];
        let attempts = two_inversion_reordered_packets(&packets).len();
        assert_eq!(attempts, 5);
    }

    #[test]
    fn one_swap_candidates_include_single_adjacent_swap() {
        let packets = vec![0, 1, 2, 3];
        let candidates = one_swap_reordered_packets(&packets);
        assert!(candidates.iter().any(|(_, c)| c == &vec![0, 2, 1, 3]));
    }

    #[test]
    fn two_swap_candidates_include_inversion_two_permutation() {
        let packets = vec![0, 1, 2, 3];
        let candidates = two_inversion_reordered_packets(&packets);
        assert!(candidates.iter().any(|(_, c)| c == &vec![1, 2, 0, 3]));
    }

    #[test]
    fn empty_for_small_packet_len() {
        let packets = vec![0, 1];
        let candidates = two_inversion_reordered_packets(&packets);
        assert!(candidates.is_empty());
    }
}
