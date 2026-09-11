// CPU-only regression guard for the Metal weight/concat cache key.
//
// The Metal weight caches reuse a GPU buffer keyed by its source slice. Keying on
// (ptr, len) alone lets a reused allocation (same address+length, different content)
// return a stale buffer. The key must also fold in the first/last element bit
// patterns so a reused pointer holding different content misses the cache.
//
// `metal_backend` is `#![cfg(feature = "metal")]` and its caches need a live
// `MetalCompute` (Device::system_default), so the real `MetalCompute::weight_cache_key`
// / `concat_cache_key` that `buf_cached`/`buf_cached_concat` call are GPU-feature gated.
// This mirrors their derivation to assert the same contract on the CPU.

/// Hardened key: pointer + length + first/last element bit patterns.
fn weight_cache_key(data: &[f32]) -> (usize, usize, u32, u32) {
    let first_bits = data.first().map(|x| x.to_bits()).unwrap_or(0);
    let last_bits = data.last().map(|x| x.to_bits()).unwrap_or(0);
    (data.as_ptr() as usize, data.len(), first_bits, last_bits)
}

fn concat_cache_key(weights: &[&[f32]]) -> Vec<(usize, usize, u32, u32)> {
    weights.iter().map(|w| weight_cache_key(w)).collect()
}

#[test]
fn legacy_ptr_len_key_collides_on_reused_allocation() {
    let mut buf = [1.0f32, 2.0, 3.0];
    let legacy_before = (buf.as_ptr() as usize, buf.len());
    buf[0] = 42.0;
    let legacy_after = (buf.as_ptr() as usize, buf.len());
    assert_eq!(
        legacy_before, legacy_after,
        "the (ptr,len)-only key cannot distinguish reused-allocation/different-content"
    );
}

#[test]
fn hardened_key_changes_when_first_element_changes() {
    let mut buf = vec![1.0f32, 2.0, 3.0, 4.0];
    let k1 = weight_cache_key(&buf);
    buf[0] = 9.0;
    let k2 = weight_cache_key(&buf);
    assert_eq!(
        (k1.0, k1.1),
        (k2.0, k2.1),
        "same allocation: ptr+len unchanged"
    );
    assert_ne!(
        k1, k2,
        "content change must change the key (no stale cache hit)"
    );
}

#[test]
fn hardened_key_changes_when_last_element_changes() {
    let mut buf = vec![1.0f32, 2.0, 3.0, 4.0];
    let k1 = weight_cache_key(&buf);
    let last = buf.len() - 1;
    buf[last] = -7.0;
    let k2 = weight_cache_key(&buf);
    assert_eq!((k1.0, k1.1), (k2.0, k2.1));
    assert_ne!(k1, k2, "last-element change must change the key");
}

#[test]
fn hardened_key_is_stable_for_identical_content() {
    let buf = vec![0.5f32, 1.5, 2.5];
    assert_eq!(
        weight_cache_key(&buf),
        weight_cache_key(&buf),
        "stable weights must still hit (no throughput regression)"
    );
}

#[test]
fn empty_slice_has_a_defined_key() {
    let empty: Vec<f32> = Vec::new();
    let k = weight_cache_key(&empty);
    assert_eq!(
        (k.1, k.2, k.3),
        (0, 0, 0),
        "empty slice: len and bit fields default to 0"
    );
}

#[test]
fn concat_key_tracks_each_component_content() {
    let mut a = vec![1.0f32, 2.0];
    let b = vec![3.0f32, 4.0];
    let k1 = concat_cache_key(&[&a, &b]);
    a[1] = 9.0;
    let k2 = concat_cache_key(&[&a, &b]);
    assert_eq!(k1.len(), k2.len());
    assert_ne!(
        k1, k2,
        "a component content change must change the concat key"
    );
}
