#[cfg(not(feature = "rustc-dep-of-std"))]
pub use std::time::Instant;

#[cfg(feature = "rustc-dep-of-std")]
use core::ops::{Add, AddAssign};
#[cfg(feature = "rustc-dep-of-std")]
use core::time::Duration;

#[cfg(feature = "rustc-dep-of-std")]
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Instant(Duration);

#[cfg(feature = "rustc-dep-of-std")]
impl Instant {
    pub const fn from_duration(duration: Duration) -> Self {
        Self(duration)
    }

    pub fn duration_since(self, earlier: Self) -> Duration {
        self.0.saturating_sub(earlier.0)
    }
}

#[cfg(feature = "rustc-dep-of-std")]
impl Add<Duration> for Instant {
    type Output = Self;

    fn add(self, rhs: Duration) -> Self::Output {
        Self(self.0 + rhs)
    }
}

#[cfg(feature = "rustc-dep-of-std")]
impl AddAssign<Duration> for Instant {
    fn add_assign(&mut self, rhs: Duration) {
        self.0 += rhs;
    }
}
