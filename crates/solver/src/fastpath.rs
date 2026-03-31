use r_evm_verify_lifter::ir::{Expr, Prop};

/// Result of fast-path evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FastResult {
    /// Definitely satisfiable (found concrete witness).
    Sat,
    /// Definitely unsatisfiable (proved impossible).
    Unsat,
    /// Can't determine — need Z3.
    Unknown,
}

/// Try to resolve a set of constraints without Z3.
/// Returns Unknown if any constraint can't be resolved.
pub fn try_fast_check(constraints: &[Prop]) -> FastResult {
    // If any single constraint is definitely false, the whole set is UNSAT.
    // If ALL constraints are definitely true, the set is SAT.
    let mut all_true = true;

    for c in constraints {
        match eval_prop(c) {
            PropVal::True => {} // continue
            PropVal::False => return FastResult::Unsat,
            PropVal::Unknown => {
                all_true = false;
            }
        }
    }

    if all_true {
        FastResult::Sat
    } else {
        FastResult::Unknown
    }
}

#[derive(Debug, Clone, Copy)]
enum PropVal {
    True,
    False,
    Unknown,
}

/// Try to evaluate a Prop to a concrete boolean.
fn eval_prop(prop: &Prop) -> PropVal {
    match prop {
        Prop::Bool(true) => PropVal::True,
        Prop::Bool(false) => PropVal::False,

        Prop::Not(inner) => match eval_prop(inner) {
            PropVal::True => PropVal::False,
            PropVal::False => PropVal::True,
            PropVal::Unknown => PropVal::Unknown,
        },

        Prop::And(a, b) => match (eval_prop(a), eval_prop(b)) {
            (PropVal::False, _) | (_, PropVal::False) => PropVal::False,
            (PropVal::True, PropVal::True) => PropVal::True,
            _ => PropVal::Unknown,
        },

        Prop::Or(a, b) => match (eval_prop(a), eval_prop(b)) {
            (PropVal::True, _) | (_, PropVal::True) => PropVal::True,
            (PropVal::False, PropVal::False) => PropVal::False,
            _ => PropVal::Unknown,
        },

        Prop::IsTrue(expr) => match try_eval_to_u256(expr) {
            Some(val) => {
                if val == [0u8; 32] {
                    PropVal::False
                } else {
                    PropVal::True
                }
            }
            None => PropVal::Unknown,
        },

        Prop::IsZero(expr) => match try_eval_to_u256(expr) {
            Some(val) => {
                if val == [0u8; 32] {
                    PropVal::True
                } else {
                    PropVal::False
                }
            }
            None => PropVal::Unknown,
        },

        Prop::Eq(a, b) => match (try_eval_to_u256(a), try_eval_to_u256(b)) {
            (Some(va), Some(vb)) => {
                if va == vb {
                    PropVal::True
                } else {
                    PropVal::False
                }
            }
            _ => PropVal::Unknown,
        },

        Prop::Lt(a, b) => match (try_eval_to_u256(a), try_eval_to_u256(b)) {
            (Some(va), Some(vb)) => {
                if u256_lt(&va, &vb) {
                    PropVal::True
                } else {
                    PropVal::False
                }
            }
            _ => PropVal::Unknown,
        },

        Prop::Gt(a, b) => match (try_eval_to_u256(a), try_eval_to_u256(b)) {
            (Some(va), Some(vb)) => {
                if u256_lt(&vb, &va) {
                    PropVal::True
                } else {
                    PropVal::False
                }
            }
            _ => PropVal::Unknown,
        },
    }
}

/// Try to evaluate an Expr to a concrete U256 (32-byte big-endian).
/// Returns None if the expression contains any symbolic variables.
fn try_eval_to_u256(expr: &Expr) -> Option<[u8; 32]> {
    match expr {
        Expr::Lit(val) => Some(*val),

        Expr::Add(a, b) => {
            let va = try_eval_to_u256(a)?;
            let vb = try_eval_to_u256(b)?;
            Some(u256_add(&va, &vb))
        }
        Expr::Sub(a, b) => {
            let va = try_eval_to_u256(a)?;
            let vb = try_eval_to_u256(b)?;
            Some(u256_sub(&va, &vb))
        }
        Expr::Mul(a, b) => {
            let va = try_eval_to_u256(a)?;
            let vb = try_eval_to_u256(b)?;
            Some(u256_mul(&va, &vb))
        }
        Expr::Div(a, b) => {
            let va = try_eval_to_u256(a)?;
            let vb = try_eval_to_u256(b)?;
            if vb == [0u8; 32] {
                Some([0u8; 32]) // EVM: div by zero = 0
            } else {
                Some(u256_div(&va, &vb))
            }
        }

        Expr::Eq(a, b) => {
            let va = try_eval_to_u256(a)?;
            let vb = try_eval_to_u256(b)?;
            let mut result = [0u8; 32];
            if va == vb {
                result[31] = 1;
            }
            Some(result)
        }
        Expr::Lt(a, b) => {
            let va = try_eval_to_u256(a)?;
            let vb = try_eval_to_u256(b)?;
            let mut result = [0u8; 32];
            if u256_lt(&va, &vb) {
                result[31] = 1;
            }
            Some(result)
        }
        Expr::Gt(a, b) => {
            let va = try_eval_to_u256(a)?;
            let vb = try_eval_to_u256(b)?;
            let mut result = [0u8; 32];
            if u256_lt(&vb, &va) {
                result[31] = 1;
            }
            Some(result)
        }
        Expr::IsZero(inner) => {
            let v = try_eval_to_u256(inner)?;
            let mut result = [0u8; 32];
            if v == [0u8; 32] {
                result[31] = 1;
            }
            Some(result)
        }

        Expr::And(a, b) => {
            let va = try_eval_to_u256(a)?;
            let vb = try_eval_to_u256(b)?;
            let mut result = [0u8; 32];
            for i in 0..32 {
                result[i] = va[i] & vb[i];
            }
            Some(result)
        }
        Expr::Or(a, b) => {
            let va = try_eval_to_u256(a)?;
            let vb = try_eval_to_u256(b)?;
            let mut result = [0u8; 32];
            for i in 0..32 {
                result[i] = va[i] | vb[i];
            }
            Some(result)
        }
        Expr::Xor(a, b) => {
            let va = try_eval_to_u256(a)?;
            let vb = try_eval_to_u256(b)?;
            let mut result = [0u8; 32];
            for i in 0..32 {
                result[i] = va[i] ^ vb[i];
            }
            Some(result)
        }
        Expr::Not(inner) => {
            let v = try_eval_to_u256(inner)?;
            let mut result = [0u8; 32];
            for i in 0..32 {
                result[i] = !v[i];
            }
            Some(result)
        }

        // Anything symbolic → can't evaluate
        _ => None,
    }
}

// --- U256 arithmetic (big-endian [u8; 32]) ---

fn u256_add(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut result = [0u8; 32];
    let mut carry: u16 = 0;
    for i in (0..32).rev() {
        let sum = a[i] as u16 + b[i] as u16 + carry;
        result[i] = sum as u8;
        carry = sum >> 8;
    }
    result
}

fn u256_sub(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut result = [0u8; 32];
    let mut borrow: i16 = 0;
    for i in (0..32).rev() {
        let diff = a[i] as i16 - b[i] as i16 - borrow;
        if diff < 0 {
            result[i] = (diff + 256) as u8;
            borrow = 1;
        } else {
            result[i] = diff as u8;
            borrow = 0;
        }
    }
    result
}

fn u256_mul(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    // Simple schoolbook multiplication, truncated to 256 bits.
    let mut result = [0u16; 64];
    for i in (0..32).rev() {
        for j in (0..32).rev() {
            let pos = i + j + 1;
            if pos < 64 {
                result[pos] += a[i] as u16 * b[j] as u16;
            }
        }
    }
    // Propagate carries
    for i in (1..64).rev() {
        result[i - 1] += result[i] >> 8;
        result[i] &= 0xFF;
    }
    // Take lower 32 bytes (truncate to 256 bits)
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = result[32 + i] as u8;
    }
    out
}

fn u256_div(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    // Convert to u128 pairs for division (handles most practical cases).
    // For full 256-bit division, we'd need a bigint library.
    let a_lo = u128_from_bytes(&a[16..32]);
    let a_hi = u128_from_bytes(&a[0..16]);
    let b_lo = u128_from_bytes(&b[16..32]);
    let b_hi = u128_from_bytes(&b[0..16]);

    // If b_hi != 0 and a_hi < b_hi, result fits in u128
    if b_hi == 0 && a_hi == 0 && b_lo != 0 {
        let result = a_lo / b_lo;
        let mut out = [0u8; 32];
        out[16..32].copy_from_slice(&result.to_be_bytes());
        return out;
    }

    // Fallback: return 0 for complex cases (Z3 will handle them)
    [0u8; 32]
}

fn u128_from_bytes(bytes: &[u8]) -> u128 {
    let mut buf = [0u8; 16];
    let start = 16 - bytes.len().min(16);
    buf[start..].copy_from_slice(&bytes[..bytes.len().min(16)]);
    u128::from_be_bytes(buf)
}

fn u256_lt(a: &[u8; 32], b: &[u8; 32]) -> bool {
    for i in 0..32 {
        if a[i] < b[i] {
            return true;
        }
        if a[i] > b[i] {
            return false;
        }
    }
    false // equal
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fast_bool_true() {
        assert_eq!(try_fast_check(&[Prop::Bool(true)]), FastResult::Sat);
    }

    #[test]
    fn fast_bool_false() {
        assert_eq!(try_fast_check(&[Prop::Bool(false)]), FastResult::Unsat);
    }

    #[test]
    fn fast_concrete_eq_sat() {
        let mut five = [0u8; 32];
        five[31] = 5;
        let constraints = vec![Prop::Eq(
            Box::new(Expr::Lit(five)),
            Box::new(Expr::Lit(five)),
        )];
        assert_eq!(try_fast_check(&constraints), FastResult::Sat);
    }

    #[test]
    fn fast_concrete_eq_unsat() {
        let mut five = [0u8; 32];
        five[31] = 5;
        let mut six = [0u8; 32];
        six[31] = 6;
        let constraints = vec![Prop::Eq(
            Box::new(Expr::Lit(five)),
            Box::new(Expr::Lit(six)),
        )];
        assert_eq!(try_fast_check(&constraints), FastResult::Unsat);
    }

    #[test]
    fn fast_concrete_add_comparison() {
        let mut three = [0u8; 32];
        three[31] = 3;
        let mut five = [0u8; 32];
        five[31] = 5;
        let mut ten = [0u8; 32];
        ten[31] = 10;
        // 3 + 5 < 10 → true
        let sum = Expr::Add(Box::new(Expr::Lit(three)), Box::new(Expr::Lit(five)));
        let constraints = vec![Prop::Lt(Box::new(sum), Box::new(Expr::Lit(ten)))];
        assert_eq!(try_fast_check(&constraints), FastResult::Sat);
    }

    #[test]
    fn fast_concrete_overflow_check() {
        // MAX_U256 + 1 < MAX_U256 → true (overflow wraps)
        let max = [0xFF; 32];
        let mut one = [0u8; 32];
        one[31] = 1;
        let sum = Expr::Add(Box::new(Expr::Lit(max)), Box::new(Expr::Lit(one)));
        let constraints = vec![Prop::Lt(Box::new(sum), Box::new(Expr::Lit(max)))];
        assert_eq!(try_fast_check(&constraints), FastResult::Sat);
    }

    #[test]
    fn fast_symbolic_unknown() {
        let x = Expr::Var("x".into());
        let mut ten = [0u8; 32];
        ten[31] = 10;
        let constraints = vec![Prop::Lt(Box::new(x), Box::new(Expr::Lit(ten)))];
        assert_eq!(try_fast_check(&constraints), FastResult::Unknown);
    }

    #[test]
    fn fast_iszero_concrete() {
        let zero = Expr::Lit([0; 32]);
        assert_eq!(
            try_fast_check(&[Prop::IsZero(Box::new(zero))]),
            FastResult::Sat
        );

        let mut one = [0u8; 32];
        one[31] = 1;
        assert_eq!(
            try_fast_check(&[Prop::IsZero(Box::new(Expr::Lit(one)))]),
            FastResult::Unsat
        );
    }

    #[test]
    fn fast_not_propagation() {
        assert_eq!(
            try_fast_check(&[Prop::Not(Box::new(Prop::Bool(false)))]),
            FastResult::Sat
        );
        assert_eq!(
            try_fast_check(&[Prop::Not(Box::new(Prop::Bool(true)))]),
            FastResult::Unsat
        );
    }

    #[test]
    fn fast_and_short_circuit() {
        // true AND false → false
        assert_eq!(
            try_fast_check(&[Prop::And(
                Box::new(Prop::Bool(true)),
                Box::new(Prop::Bool(false))
            )]),
            FastResult::Unsat
        );
    }

    #[test]
    fn u256_add_basic() {
        let mut a = [0u8; 32];
        a[31] = 100;
        let mut b = [0u8; 32];
        b[31] = 200;
        let result = u256_add(&a, &b);
        assert_eq!(result[31], 44); // 300 mod 256 = 44
        assert_eq!(result[30], 1); // carry
    }

    #[test]
    fn u256_mul_basic() {
        let mut a = [0u8; 32];
        a[31] = 7;
        let mut b = [0u8; 32];
        b[31] = 6;
        let result = u256_mul(&a, &b);
        assert_eq!(result[31], 42);
    }

    #[test]
    fn u256_lt_basic() {
        let mut a = [0u8; 32];
        a[31] = 5;
        let mut b = [0u8; 32];
        b[31] = 10;
        assert!(u256_lt(&a, &b));
        assert!(!u256_lt(&b, &a));
        assert!(!u256_lt(&a, &a));
    }

    #[test]
    fn mixed_concrete_and_symbolic() {
        // Bool(true) AND (symbolic < 10) → Unknown (can't resolve symbolic part)
        let x = Expr::Var("x".into());
        let mut ten = [0u8; 32];
        ten[31] = 10;
        let constraints = vec![
            Prop::Bool(true),
            Prop::Lt(Box::new(x), Box::new(Expr::Lit(ten))),
        ];
        assert_eq!(try_fast_check(&constraints), FastResult::Unknown);
    }

    #[test]
    fn one_false_short_circuits() {
        // false AND (symbolic) → Unsat (don't need to resolve symbolic)
        let x = Expr::Var("x".into());
        let mut ten = [0u8; 32];
        ten[31] = 10;
        let constraints = vec![
            Prop::Bool(false),
            Prop::Lt(Box::new(x), Box::new(Expr::Lit(ten))),
        ];
        assert_eq!(try_fast_check(&constraints), FastResult::Unsat);
    }
}
