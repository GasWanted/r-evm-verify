use crate::SolverError;
use r_evm_verify_lifter::ir::{Expr, Prop};
use z3::ast::{Ast, Bool, BV as BitVec};

/// Translate an Expr to a Z3 256-bit bitvector AST.
pub fn expr_to_z3<'ctx>(ctx: &'ctx z3::Context, expr: &Expr) -> Result<BitVec<'ctx>, SolverError> {
    match expr {
        Expr::Lit(bytes) => {
            // Build 256-bit BV from 4 x 64-bit chunks.
            let chunk = |start: usize| -> u64 {
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&bytes[start..start + 8]);
                u64::from_be_bytes(buf)
            };
            let hi3 = BitVec::from_u64(ctx, chunk(0), 64);
            let hi2 = BitVec::from_u64(ctx, chunk(8), 64);
            let hi1 = BitVec::from_u64(ctx, chunk(16), 64);
            let lo = BitVec::from_u64(ctx, chunk(24), 64);
            Ok(hi3.concat(&hi2).concat(&hi1).concat(&lo))
        }
        Expr::Var(name) => Ok(BitVec::new_const(ctx, name.as_str(), 256)),

        // Arithmetic
        Expr::Add(a, b) => Ok(expr_to_z3(ctx, a)?.bvadd(&expr_to_z3(ctx, b)?)),
        Expr::Sub(a, b) => Ok(expr_to_z3(ctx, a)?.bvsub(&expr_to_z3(ctx, b)?)),
        Expr::Mul(a, b) => Ok(expr_to_z3(ctx, a)?.bvmul(&expr_to_z3(ctx, b)?)),
        Expr::Div(a, b) => Ok(expr_to_z3(ctx, a)?.bvudiv(&expr_to_z3(ctx, b)?)),
        Expr::SDiv(a, b) => Ok(expr_to_z3(ctx, a)?.bvsdiv(&expr_to_z3(ctx, b)?)),
        Expr::Mod(a, b) => Ok(expr_to_z3(ctx, a)?.bvurem(&expr_to_z3(ctx, b)?)),
        Expr::SMod(a, b) => Ok(expr_to_z3(ctx, a)?.bvsrem(&expr_to_z3(ctx, b)?)),
        Expr::Exp(a, b) => {
            // Z3 doesn't have native bitvector exponentiation.
            // Return an uninterpreted function for now.
            let f = z3::FuncDecl::new(
                ctx,
                "bvexp",
                &[
                    &z3::Sort::bitvector(ctx, 256),
                    &z3::Sort::bitvector(ctx, 256),
                ],
                &z3::Sort::bitvector(ctx, 256),
            );
            Ok(f.apply(&[&expr_to_z3(ctx, a)?, &expr_to_z3(ctx, b)?])
                .as_bv()
                .unwrap())
        }

        // Comparison — return 1 or 0 as 256-bit
        Expr::Lt(a, b) => {
            let cond = expr_to_z3(ctx, a)?.bvult(&expr_to_z3(ctx, b)?);
            Ok(cond.ite(
                &BitVec::from_u64(ctx, 1, 256),
                &BitVec::from_u64(ctx, 0, 256),
            ))
        }
        Expr::Gt(a, b) => {
            let cond = expr_to_z3(ctx, a)?.bvugt(&expr_to_z3(ctx, b)?);
            Ok(cond.ite(
                &BitVec::from_u64(ctx, 1, 256),
                &BitVec::from_u64(ctx, 0, 256),
            ))
        }
        Expr::Eq(a, b) => {
            let cond = expr_to_z3(ctx, a)?._eq(&expr_to_z3(ctx, b)?);
            Ok(cond.ite(
                &BitVec::from_u64(ctx, 1, 256),
                &BitVec::from_u64(ctx, 0, 256),
            ))
        }
        Expr::IsZero(a) => {
            let zero = BitVec::from_u64(ctx, 0, 256);
            let cond = expr_to_z3(ctx, a)?._eq(&zero);
            Ok(cond.ite(
                &BitVec::from_u64(ctx, 1, 256),
                &BitVec::from_u64(ctx, 0, 256),
            ))
        }

        // Bitwise
        Expr::And(a, b) => Ok(expr_to_z3(ctx, a)?.bvand(&expr_to_z3(ctx, b)?)),
        Expr::Or(a, b) => Ok(expr_to_z3(ctx, a)?.bvor(&expr_to_z3(ctx, b)?)),
        Expr::Xor(a, b) => Ok(expr_to_z3(ctx, a)?.bvxor(&expr_to_z3(ctx, b)?)),
        Expr::Not(a) => Ok(expr_to_z3(ctx, a)?.bvnot()),
        Expr::Shl(shift, val) => Ok(expr_to_z3(ctx, val)?.bvshl(&expr_to_z3(ctx, shift)?)),
        Expr::Shr(shift, val) => Ok(expr_to_z3(ctx, val)?.bvlshr(&expr_to_z3(ctx, shift)?)),
        Expr::Sar(shift, val) => Ok(expr_to_z3(ctx, val)?.bvashr(&expr_to_z3(ctx, shift)?)),

        // Storage/Memory — model as uninterpreted functions
        Expr::SLoad(slot) => {
            let f = z3::FuncDecl::new(
                ctx,
                "sload",
                &[&z3::Sort::bitvector(ctx, 256)],
                &z3::Sort::bitvector(ctx, 256),
            );
            Ok(f.apply(&[&expr_to_z3(ctx, slot)?]).as_bv().unwrap())
        }
        Expr::MLoad(offset) => {
            let f = z3::FuncDecl::new(
                ctx,
                "mload",
                &[&z3::Sort::bitvector(ctx, 256)],
                &z3::Sort::bitvector(ctx, 256),
            );
            Ok(f.apply(&[&expr_to_z3(ctx, offset)?]).as_bv().unwrap())
        }
        Expr::Keccak256(input) => {
            let f = z3::FuncDecl::new(
                ctx,
                "keccak256",
                &[&z3::Sort::bitvector(ctx, 256)],
                &z3::Sort::bitvector(ctx, 256),
            );
            Ok(f.apply(&[&expr_to_z3(ctx, input)?]).as_bv().unwrap())
        }

        // Environment — fresh symbolic constants
        Expr::Caller => Ok(BitVec::new_const(ctx, "caller", 256)),
        Expr::CallValue => Ok(BitVec::new_const(ctx, "callvalue", 256)),
        Expr::CallDataLoad(offset) => {
            let f = z3::FuncDecl::new(
                ctx,
                "calldataload",
                &[&z3::Sort::bitvector(ctx, 256)],
                &z3::Sort::bitvector(ctx, 256),
            );
            Ok(f.apply(&[&expr_to_z3(ctx, offset)?]).as_bv().unwrap())
        }
        Expr::CallDataSize => Ok(BitVec::new_const(ctx, "calldatasize", 256)),
        Expr::Address => Ok(BitVec::new_const(ctx, "address", 256)),
        Expr::Origin => Ok(BitVec::new_const(ctx, "origin", 256)),
        Expr::GasPrice => Ok(BitVec::new_const(ctx, "gasprice", 256)),
        Expr::Coinbase => Ok(BitVec::new_const(ctx, "coinbase", 256)),
        Expr::Timestamp => Ok(BitVec::new_const(ctx, "timestamp", 256)),
        Expr::Number => Ok(BitVec::new_const(ctx, "blocknumber", 256)),
        Expr::GasLimit => Ok(BitVec::new_const(ctx, "gaslimit", 256)),
        Expr::ChainId => Ok(BitVec::new_const(ctx, "chainid", 256)),
        Expr::Balance(addr) => {
            let f = z3::FuncDecl::new(
                ctx,
                "balance",
                &[&z3::Sort::bitvector(ctx, 256)],
                &z3::Sort::bitvector(ctx, 256),
            );
            Ok(f.apply(&[&expr_to_z3(ctx, addr)?]).as_bv().unwrap())
        }
        Expr::BlockHash(num) => {
            let f = z3::FuncDecl::new(
                ctx,
                "blockhash",
                &[&z3::Sort::bitvector(ctx, 256)],
                &z3::Sort::bitvector(ctx, 256),
            );
            Ok(f.apply(&[&expr_to_z3(ctx, num)?]).as_bv().unwrap())
        }

        _ => Err(SolverError::Unsupported(format!("{:?}", expr))),
    }
}

/// Translate a Prop to a Z3 boolean AST.
pub fn prop_to_z3<'ctx>(ctx: &'ctx z3::Context, prop: &Prop) -> Result<Bool<'ctx>, SolverError> {
    match prop {
        Prop::Bool(true) => Ok(Bool::from_bool(ctx, true)),
        Prop::Bool(false) => Ok(Bool::from_bool(ctx, false)),
        Prop::IsTrue(expr) => {
            let bv = expr_to_z3(ctx, expr)?;
            let zero = BitVec::from_u64(ctx, 0, 256);
            Ok(bv._eq(&zero).not())
        }
        Prop::IsZero(expr) => {
            let bv = expr_to_z3(ctx, expr)?;
            let zero = BitVec::from_u64(ctx, 0, 256);
            Ok(bv._eq(&zero))
        }
        Prop::Eq(a, b) => Ok(expr_to_z3(ctx, a)?._eq(&expr_to_z3(ctx, b)?)),
        Prop::Lt(a, b) => Ok(expr_to_z3(ctx, a)?.bvult(&expr_to_z3(ctx, b)?)),
        Prop::Gt(a, b) => Ok(expr_to_z3(ctx, a)?.bvugt(&expr_to_z3(ctx, b)?)),
        Prop::And(a, b) => Ok(Bool::and(
            ctx,
            &[&prop_to_z3(ctx, a)?, &prop_to_z3(ctx, b)?],
        )),
        Prop::Or(a, b) => Ok(Bool::or(ctx, &[&prop_to_z3(ctx, a)?, &prop_to_z3(ctx, b)?])),
        Prop::Not(a) => Ok(prop_to_z3(ctx, a)?.not()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn translate_literal() {
        let ctx = z3::Context::new(&z3::Config::new());
        let mut bytes = [0u8; 32];
        bytes[31] = 42;
        let bv = expr_to_z3(&ctx, &Expr::Lit(bytes)).unwrap();
        // Verify via solver: bv == 42
        let solver = z3::Solver::new(&ctx);
        let forty_two = BitVec::from_u64(&ctx, 42, 256);
        solver.assert(&bv._eq(&forty_two));
        assert_eq!(solver.check(), z3::SatResult::Sat);
        // And bv != 43
        let solver2 = z3::Solver::new(&ctx);
        let forty_three = BitVec::from_u64(&ctx, 43, 256);
        solver2.assert(&bv._eq(&forty_three));
        assert_eq!(solver2.check(), z3::SatResult::Unsat);
    }

    #[test]
    fn translate_add() {
        let ctx = z3::Context::new(&z3::Config::new());
        let a = Expr::Var("a".into());
        let b = Expr::Var("b".into());
        let sum = Expr::Add(Box::new(a), Box::new(b));
        let bv = expr_to_z3(&ctx, &sum).unwrap();
        assert!(bv.to_string().contains("bvadd"));
    }

    #[test]
    fn translate_prop_and() {
        let ctx = z3::Context::new(&z3::Config::new());
        let prop = Prop::And(Box::new(Prop::Bool(true)), Box::new(Prop::Bool(true)));
        let z3_prop = prop_to_z3(&ctx, &prop).unwrap();
        let solver = z3::Solver::new(&ctx);
        solver.assert(&z3_prop);
        assert_eq!(solver.check(), z3::SatResult::Sat);
    }
}
