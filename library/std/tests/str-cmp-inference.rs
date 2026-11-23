use std::cmp::Ordering;

fn str_partial_cmp(a: &str, b: &&str) -> Option<Ordering> {
    a.partial_cmp(b)
}

fn slice_partial_cmp(a: &[u8], b: &&[u8]) -> Option<Ordering> {
    a.partial_cmp(b)
}

#[test]
fn str_partial_cmp_infers_rhs() {
    assert_eq!(str_partial_cmp("a", &"b"), Some(Ordering::Less));
}

#[test]
fn slice_partial_cmp_infers_rhs() {
    assert_eq!(slice_partial_cmp(b"b", &&b"a"[..]), Some(Ordering::Greater));
}
