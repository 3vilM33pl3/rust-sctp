//! Minimal slab allocator: stable `usize` keys for values that come and go,
//! with freed slots reused. Replaces the `slab` crate for the handful of
//! operations the endpoint needs.

use alloc::vec::Vec;
use core::ops::{Index, IndexMut};

#[derive(Debug)]
pub(crate) struct Slab<T> {
    entries: Vec<Option<T>>,
    free: Vec<usize>,
    len: usize,
}

impl<T> Slab<T> {
    pub(crate) const fn new() -> Self {
        Self { entries: Vec::new(), free: Vec::new(), len: 0 }
    }

    pub(crate) fn insert(&mut self, value: T) -> usize {
        self.len += 1;
        match self.free.pop() {
            Some(key) => {
                self.entries[key] = Some(value);
                key
            }
            None => {
                self.entries.push(Some(value));
                self.entries.len() - 1
            }
        }
    }

    /// Removes and returns the value at `key`.
    ///
    /// # Panics
    ///
    /// Panics if `key` is not occupied, like the `slab` crate.
    pub(crate) fn remove(&mut self, key: usize) -> T {
        let value = self.entries[key].take().expect("invalid key");
        self.free.push(key);
        self.len -= 1;
        value
    }

    pub(crate) fn contains(&self, key: usize) -> bool {
        matches!(self.entries.get(key), Some(Some(_)))
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }
}

impl<T> Index<usize> for Slab<T> {
    type Output = T;
    fn index(&self, key: usize) -> &T {
        self.entries[key].as_ref().expect("invalid key")
    }
}

impl<T> IndexMut<usize> for Slab<T> {
    fn index_mut(&mut self, key: usize) -> &mut T {
        self.entries[key].as_mut().expect("invalid key")
    }
}

#[cfg(test)]
mod tests {
    use super::Slab;

    #[test]
    fn reuses_freed_keys_and_tracks_len() {
        let mut s = Slab::new();
        let a = s.insert("a");
        let b = s.insert("b");
        assert_eq!((s.len(), s[a], s[b]), (2, "a", "b"));
        assert_eq!(s.remove(a), "a");
        assert!(!s.contains(a) && s.contains(b));
        let c = s.insert("c");
        assert_eq!((c, s.len(), s[c]), (a, 2, "c"));
    }
}
