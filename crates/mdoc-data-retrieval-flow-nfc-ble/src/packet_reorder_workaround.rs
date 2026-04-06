use anyhow::Result;
use log::warn;
use std::collections::HashSet;

pub(crate) fn try_decode_and_decrypt_session_data<T, F>(packets: &[Vec<u8>], decode: F) -> Result<T>
where
    F: Fn(&[u8]) -> Result<T>,
{
    let joined = join_packets(packets);
    if let Ok(message) = decode(&joined) {
        return Ok(message);
    }

    let packet_len = packets.len();
    if packet_len < 2 {
        return decode(&joined);
    }

    for (swap_at, swapped) in one_swap_reordered_packets(packets) {
        let candidate = join_packets(&swapped);
        if let Ok(message) = decode(&candidate) {
            warn!(
                "session data recovered by swapping packet {} and {}",
                swap_at,
                swap_at + 1
            );
            return Ok(message);
        }
    }

    if packet_len >= 3 {
        for (permutation, reordered) in two_inversion_reordered_packets(packets) {
            let candidate = join_packets(&reordered);
            if let Ok(message) = decode(&candidate) {
                warn!(
                    "session data recovered by inversion-2 permutation {:?}",
                    permutation
                );
                return Ok(message);
            }
        }
    }

    decode(&joined)
}

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

pub(crate) fn join_packets(packets: &[Vec<u8>]) -> Vec<u8> {
    let total_len: usize = packets.iter().map(Vec::len).sum();
    let mut joined = Vec::with_capacity(total_len);
    for packet in packets {
        joined.extend_from_slice(packet);
    }
    joined
}

#[cfg(test)]
mod tests {
    use super::{
        join_packets, one_swap_indices, one_swap_reordered_packets,
        try_decode_and_decrypt_session_data, two_inversion_reordered_packets,
    };

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

    #[test]
    fn join_packets_concatenates_in_order() {
        let packets = vec![vec![1u8, 2], vec![3, 4]];
        assert_eq!(join_packets(&packets), vec![1, 2, 3, 4]);
    }

    #[test]
    fn try_decode_recovers_from_one_swap() {
        let packets = vec![vec![2u8], vec![1], vec![3]];
        let decoded = try_decode_and_decrypt_session_data(&packets, |joined| {
            if joined == [1, 2, 3] {
                Ok(joined.to_vec())
            } else {
                anyhow::bail!("not decodable")
            }
        })
        .expect("should recover by packet swap");
        assert_eq!(decoded, vec![1, 2, 3]);
    }
}
