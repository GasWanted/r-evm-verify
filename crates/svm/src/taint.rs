/// Taint level for tracking data flow from untrusted sources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Taint {
    /// From attacker-controlled source: calldata, msg.value, msg.sender args
    Untrusted,
    /// From known-safe source: constants, known admin storage
    Trusted,
    /// Unknown origin (default for SLOAD)
    Unknown,
}

impl Taint {
    /// Combine taints: Untrusted dominates Unknown dominates Trusted.
    pub fn combine(self, other: Taint) -> Taint {
        match (self, other) {
            (Taint::Untrusted, _) | (_, Taint::Untrusted) => Taint::Untrusted,
            (Taint::Unknown, _) | (_, Taint::Unknown) => Taint::Unknown,
            (Taint::Trusted, Taint::Trusted) => Taint::Trusted,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn combine_untrusted_dominates() {
        assert_eq!(Taint::Untrusted.combine(Taint::Trusted), Taint::Untrusted);
        assert_eq!(Taint::Trusted.combine(Taint::Untrusted), Taint::Untrusted);
        assert_eq!(Taint::Untrusted.combine(Taint::Unknown), Taint::Untrusted);
    }

    #[test]
    fn combine_unknown_middle() {
        assert_eq!(Taint::Unknown.combine(Taint::Trusted), Taint::Unknown);
        assert_eq!(Taint::Trusted.combine(Taint::Unknown), Taint::Unknown);
    }

    #[test]
    fn combine_trusted_only_with_trusted() {
        assert_eq!(Taint::Trusted.combine(Taint::Trusted), Taint::Trusted);
    }
}
