use crate::ir::{Expr, Prop};

const ZERO: [u8; 32] = [0u8; 32];
const ONE: [u8; 32] = {
    let mut b = [0u8; 32];
    b[31] = 1;
    b
};
const MAX: [u8; 32] = [0xFF; 32];

/// Simplify an expression tree via constant folding and identity elimination.
pub fn simplify_expr(expr: &Expr) -> Expr {
    match expr {
        // Arithmetic identities
        Expr::Add(a, b) => {
            let a = simplify_expr(a);
            let b = simplify_expr(b);
            match (&a, &b) {
                (Expr::Lit(ZERO), _) => b,                                     // 0 + x = x
                (_, Expr::Lit(ZERO)) => a,                                     // x + 0 = x
                (Expr::Lit(va), Expr::Lit(vb)) => Expr::Lit(u256_add(va, vb)), // const fold
                _ => Expr::Add(Box::new(a), Box::new(b)),
            }
        }
        Expr::Sub(a, b) => {
            let a = simplify_expr(a);
            let b = simplify_expr(b);
            match (&a, &b) {
                (_, Expr::Lit(ZERO)) => a, // x - 0 = x
                (Expr::Lit(va), Expr::Lit(vb)) => Expr::Lit(u256_sub(va, vb)),
                _ if a == b => Expr::Lit(ZERO), // x - x = 0
                _ => Expr::Sub(Box::new(a), Box::new(b)),
            }
        }
        Expr::Mul(a, b) => {
            let a = simplify_expr(a);
            let b = simplify_expr(b);
            match (&a, &b) {
                (Expr::Lit(ZERO), _) | (_, Expr::Lit(ZERO)) => Expr::Lit(ZERO), // 0 * x = 0
                (Expr::Lit(ONE), _) => b,                                       // 1 * x = x
                (_, Expr::Lit(ONE)) => a,                                       // x * 1 = x
                (Expr::Lit(va), Expr::Lit(vb)) => Expr::Lit(u256_mul(va, vb)),
                _ => Expr::Mul(Box::new(a), Box::new(b)),
            }
        }
        Expr::Div(a, b) => {
            let a = simplify_expr(a);
            let b = simplify_expr(b);
            match (&a, &b) {
                (Expr::Lit(ZERO), _) => Expr::Lit(ZERO), // 0 / x = 0
                (_, Expr::Lit(ONE)) => a,                // x / 1 = x
                (_, Expr::Lit(ZERO)) => Expr::Lit(ZERO), // x / 0 = 0 (EVM)
                (Expr::Lit(va), Expr::Lit(vb)) => Expr::Lit(u256_div(va, vb)),
                _ if a == b => Expr::Lit(ONE), // x / x = 1
                _ => Expr::Div(Box::new(a), Box::new(b)),
            }
        }

        // Bitwise identities
        Expr::And(a, b) => {
            let a = simplify_expr(a);
            let b = simplify_expr(b);
            match (&a, &b) {
                (Expr::Lit(ZERO), _) | (_, Expr::Lit(ZERO)) => Expr::Lit(ZERO), // 0 & x = 0
                (Expr::Lit(MAX), _) => b,                                       // 0xFF..FF & x = x
                (_, Expr::Lit(MAX)) => a,
                _ if a == b => a, // x & x = x
                _ => Expr::And(Box::new(a), Box::new(b)),
            }
        }
        Expr::Or(a, b) => {
            let a = simplify_expr(a);
            let b = simplify_expr(b);
            match (&a, &b) {
                (Expr::Lit(ZERO), _) => b, // 0 | x = x
                (_, Expr::Lit(ZERO)) => a,
                (Expr::Lit(MAX), _) | (_, Expr::Lit(MAX)) => Expr::Lit(MAX),
                _ if a == b => a, // x | x = x
                _ => Expr::Or(Box::new(a), Box::new(b)),
            }
        }
        Expr::Xor(a, b) => {
            let a = simplify_expr(a);
            let b = simplify_expr(b);
            match (&a, &b) {
                (Expr::Lit(ZERO), _) => b,
                (_, Expr::Lit(ZERO)) => a,
                _ if a == b => Expr::Lit(ZERO), // x ^ x = 0
                _ => Expr::Xor(Box::new(a), Box::new(b)),
            }
        }
        Expr::Not(a) => {
            let a = simplify_expr(a);
            match &a {
                Expr::Not(inner) => simplify_expr(inner), // NOT(NOT(x)) = x
                Expr::Lit(v) => {
                    let mut result = [0u8; 32];
                    for i in 0..32 {
                        result[i] = !v[i];
                    }
                    Expr::Lit(result)
                }
                _ => Expr::Not(Box::new(a)),
            }
        }

        // Comparison simplification
        Expr::IsZero(a) => {
            let a = simplify_expr(a);
            match &a {
                Expr::Lit(ZERO) => Expr::Lit(ONE), // ISZERO(0) = 1
                Expr::Lit(_) => Expr::Lit(ZERO),   // ISZERO(nonzero) = 0
                Expr::IsZero(inner) => {
                    // ISZERO(ISZERO(x)) = x != 0 ? 1 : 0 — keep as-is for now
                    Expr::IsZero(Box::new(Expr::IsZero(inner.clone())))
                }
                _ => Expr::IsZero(Box::new(a)),
            }
        }
        Expr::Eq(a, b) => {
            let a = simplify_expr(a);
            let b = simplify_expr(b);
            if a == b {
                return Expr::Lit(ONE);
            } // x == x = 1
            match (&a, &b) {
                (Expr::Lit(va), Expr::Lit(vb)) => Expr::Lit(if va == vb { ONE } else { ZERO }),
                _ => Expr::Eq(Box::new(a), Box::new(b)),
            }
        }
        Expr::Lt(a, b) => {
            let a = simplify_expr(a);
            let b = simplify_expr(b);
            match (&a, &b) {
                (_, Expr::Lit(ZERO)) => Expr::Lit(ZERO), // x < 0 = false (unsigned)
                (Expr::Lit(va), Expr::Lit(vb)) => {
                    Expr::Lit(if u256_lt(va, vb) { ONE } else { ZERO })
                }
                _ => Expr::Lt(Box::new(a), Box::new(b)),
            }
        }
        Expr::Gt(a, b) => {
            let a = simplify_expr(a);
            let b = simplify_expr(b);
            match (&a, &b) {
                (Expr::Lit(ZERO), _) => Expr::Lit(ZERO), // 0 > x = false (unsigned)
                (Expr::Lit(va), Expr::Lit(vb)) => {
                    Expr::Lit(if u256_lt(vb, va) { ONE } else { ZERO })
                }
                _ => Expr::Gt(Box::new(a), Box::new(b)),
            }
        }

        // Shift simplification
        Expr::Shl(shift, val) => {
            let shift = simplify_expr(shift);
            let val = simplify_expr(val);
            match (&shift, &val) {
                (Expr::Lit(ZERO), _) => val,             // x << 0 = x
                (_, Expr::Lit(ZERO)) => Expr::Lit(ZERO), // 0 << n = 0
                _ => Expr::Shl(Box::new(shift), Box::new(val)),
            }
        }
        Expr::Shr(shift, val) => {
            let shift = simplify_expr(shift);
            let val = simplify_expr(val);
            match (&shift, &val) {
                (Expr::Lit(ZERO), _) => val,
                (_, Expr::Lit(ZERO)) => Expr::Lit(ZERO),
                _ => Expr::Shr(Box::new(shift), Box::new(val)),
            }
        }

        // Recursive simplification for other variants
        Expr::SDiv(a, b) => {
            let a = simplify_expr(a);
            let b = simplify_expr(b);
            Expr::SDiv(Box::new(a), Box::new(b))
        }
        Expr::Mod(a, b) => {
            let a = simplify_expr(a);
            let b = simplify_expr(b);
            match (&a, &b) {
                (Expr::Lit(ZERO), _) => Expr::Lit(ZERO),
                _ => Expr::Mod(Box::new(a), Box::new(b)),
            }
        }
        Expr::SMod(a, b) => Expr::SMod(Box::new(simplify_expr(a)), Box::new(simplify_expr(b))),
        Expr::Exp(a, b) => {
            let a = simplify_expr(a);
            let b = simplify_expr(b);
            match (&a, &b) {
                (_, Expr::Lit(ZERO)) => Expr::Lit(ONE),  // x^0 = 1
                (_, Expr::Lit(ONE)) => a,                // x^1 = x
                (Expr::Lit(ZERO), _) => Expr::Lit(ZERO), // 0^n = 0 (n>0)
                _ => Expr::Exp(Box::new(a), Box::new(b)),
            }
        }
        Expr::SLt(a, b) => Expr::SLt(Box::new(simplify_expr(a)), Box::new(simplify_expr(b))),
        Expr::SGt(a, b) => Expr::SGt(Box::new(simplify_expr(a)), Box::new(simplify_expr(b))),
        Expr::Sar(a, b) => Expr::Sar(Box::new(simplify_expr(a)), Box::new(simplify_expr(b))),
        Expr::Keccak256(a) => Expr::Keccak256(Box::new(simplify_expr(a))),
        Expr::SLoad(a) => Expr::SLoad(Box::new(simplify_expr(a))),
        Expr::MLoad(a) => Expr::MLoad(Box::new(simplify_expr(a))),
        Expr::CallDataLoad(a) => Expr::CallDataLoad(Box::new(simplify_expr(a))),
        Expr::Balance(a) => Expr::Balance(Box::new(simplify_expr(a))),
        Expr::BlockHash(a) => Expr::BlockHash(Box::new(simplify_expr(a))),
        Expr::AddMod(a, b, c) => Expr::AddMod(
            Box::new(simplify_expr(a)),
            Box::new(simplify_expr(b)),
            Box::new(simplify_expr(c)),
        ),
        Expr::MulMod(a, b, c) => Expr::MulMod(
            Box::new(simplify_expr(a)),
            Box::new(simplify_expr(b)),
            Box::new(simplify_expr(c)),
        ),
        Expr::Ite(p, a, b) => Expr::Ite(
            Box::new(simplify_prop(p)),
            Box::new(simplify_expr(a)),
            Box::new(simplify_expr(b)),
        ),

        // Leaf nodes — return as-is
        _ => expr.clone(),
    }
}

/// Simplify a proposition.
pub fn simplify_prop(prop: &Prop) -> Prop {
    match prop {
        Prop::Bool(_) => prop.clone(),
        Prop::IsTrue(e) => {
            let e = simplify_expr(e);
            match &e {
                Expr::Lit(ZERO) => Prop::Bool(false),
                Expr::Lit(_) => Prop::Bool(true),
                _ => Prop::IsTrue(Box::new(e)),
            }
        }
        Prop::IsZero(e) => {
            let e = simplify_expr(e);
            match &e {
                Expr::Lit(ZERO) => Prop::Bool(true),
                Expr::Lit(_) => Prop::Bool(false),
                _ => Prop::IsZero(Box::new(e)),
            }
        }
        Prop::Eq(a, b) => {
            let a = simplify_expr(a);
            let b = simplify_expr(b);
            if a == b {
                return Prop::Bool(true);
            }
            match (&a, &b) {
                (Expr::Lit(va), Expr::Lit(vb)) => Prop::Bool(va == vb),
                _ => Prop::Eq(Box::new(a), Box::new(b)),
            }
        }
        Prop::Lt(a, b) => {
            let a = simplify_expr(a);
            let b = simplify_expr(b);
            match (&a, &b) {
                (Expr::Lit(va), Expr::Lit(vb)) => Prop::Bool(u256_lt(va, vb)),
                _ => Prop::Lt(Box::new(a), Box::new(b)),
            }
        }
        Prop::Gt(a, b) => {
            let a = simplify_expr(a);
            let b = simplify_expr(b);
            match (&a, &b) {
                (Expr::Lit(va), Expr::Lit(vb)) => Prop::Bool(u256_lt(vb, va)),
                _ => Prop::Gt(Box::new(a), Box::new(b)),
            }
        }
        Prop::And(a, b) => {
            let a = simplify_prop(a);
            let b = simplify_prop(b);
            match (&a, &b) {
                (Prop::Bool(false), _) | (_, Prop::Bool(false)) => Prop::Bool(false),
                (Prop::Bool(true), _) => b,
                (_, Prop::Bool(true)) => a,
                _ => Prop::And(Box::new(a), Box::new(b)),
            }
        }
        Prop::Or(a, b) => {
            let a = simplify_prop(a);
            let b = simplify_prop(b);
            match (&a, &b) {
                (Prop::Bool(true), _) | (_, Prop::Bool(true)) => Prop::Bool(true),
                (Prop::Bool(false), _) => b,
                (_, Prop::Bool(false)) => a,
                _ => Prop::Or(Box::new(a), Box::new(b)),
            }
        }
        Prop::Not(a) => {
            let a = simplify_prop(a);
            match &a {
                Prop::Bool(v) => Prop::Bool(!v),
                Prop::Not(inner) => (**inner).clone(),
                _ => Prop::Not(Box::new(a)),
            }
        }
    }
}

// --- U256 helpers (big-endian [u8; 32]) ---

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
    let mut result = [0u16; 64];
    for i in (0..32).rev() {
        for j in (0..32).rev() {
            let pos = i + j + 1;
            if pos < 64 {
                result[pos] += a[i] as u16 * b[j] as u16;
            }
        }
    }
    for i in (1..64).rev() {
        result[i - 1] += result[i] >> 8;
        result[i] &= 0xFF;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = result[32 + i] as u8;
    }
    out
}

fn u256_div(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    if *b == ZERO {
        return ZERO;
    }
    // Simple: convert to u128 pairs
    let a_lo = u128_from_be(&a[16..32]);
    let b_lo = u128_from_be(&b[16..32]);
    let a_hi = u128_from_be(&a[0..16]);
    let b_hi = u128_from_be(&b[0..16]);
    if b_hi == 0 && a_hi == 0 && b_lo != 0 {
        let result = a_lo / b_lo;
        let mut out = [0u8; 32];
        out[16..32].copy_from_slice(&result.to_be_bytes());
        return out;
    }
    ZERO // fallback for huge values
}

fn u128_from_be(bytes: &[u8]) -> u128 {
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
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_zero_identity() {
        let x = Expr::Var("x".into());
        let result = simplify_expr(&Expr::Add(Box::new(Expr::Lit(ZERO)), Box::new(x.clone())));
        assert_eq!(result, x);
    }

    #[test]
    fn mul_zero() {
        let x = Expr::Var("x".into());
        let result = simplify_expr(&Expr::Mul(Box::new(Expr::Lit(ZERO)), Box::new(x)));
        assert_eq!(result, Expr::Lit(ZERO));
    }

    #[test]
    fn sub_self() {
        let x = Expr::Var("x".into());
        let result = simplify_expr(&Expr::Sub(Box::new(x.clone()), Box::new(x)));
        assert_eq!(result, Expr::Lit(ZERO));
    }

    #[test]
    fn const_fold_add() {
        let mut a = ZERO;
        a[31] = 3;
        let mut b = ZERO;
        b[31] = 5;
        let result = simplify_expr(&Expr::Add(Box::new(Expr::Lit(a)), Box::new(Expr::Lit(b))));
        let mut expected = ZERO;
        expected[31] = 8;
        assert_eq!(result, Expr::Lit(expected));
    }

    #[test]
    fn iszero_of_zero() {
        let result = simplify_expr(&Expr::IsZero(Box::new(Expr::Lit(ZERO))));
        assert_eq!(result, Expr::Lit(ONE));
    }

    #[test]
    fn not_not_cancels() {
        let x = Expr::Var("x".into());
        let result = simplify_expr(&Expr::Not(Box::new(Expr::Not(Box::new(x.clone())))));
        assert_eq!(result, x);
    }

    #[test]
    fn prop_and_true() {
        let x = Prop::IsTrue(Box::new(Expr::Var("x".into())));
        let result = simplify_prop(&Prop::And(Box::new(Prop::Bool(true)), Box::new(x.clone())));
        assert_eq!(result, x);
    }

    #[test]
    fn prop_or_false() {
        let x = Prop::IsTrue(Box::new(Expr::Var("x".into())));
        let result = simplify_prop(&Prop::Or(Box::new(Prop::Bool(false)), Box::new(x.clone())));
        assert_eq!(result, x);
    }

    #[test]
    fn nested_simplification() {
        // (x + 0) * 1 → x
        let x = Expr::Var("x".into());
        let expr = Expr::Mul(
            Box::new(Expr::Add(Box::new(x.clone()), Box::new(Expr::Lit(ZERO)))),
            Box::new(Expr::Lit(ONE)),
        );
        assert_eq!(simplify_expr(&expr), x);
    }
}
