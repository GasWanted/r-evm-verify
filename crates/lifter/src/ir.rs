use crate::opcodes::Opcode;
use serde::{Deserialize, Serialize};

/// A 256-bit value stored as 32 bytes (big-endian).
pub type U256Bytes = [u8; 32];

/// Symbolic expression representing an EVM value.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Expr {
    /// Concrete 256-bit literal.
    Lit(U256Bytes),
    /// Named symbolic variable.
    Var(String),

    // Arithmetic
    Add(Box<Expr>, Box<Expr>),
    Sub(Box<Expr>, Box<Expr>),
    Mul(Box<Expr>, Box<Expr>),
    Div(Box<Expr>, Box<Expr>),
    SDiv(Box<Expr>, Box<Expr>),
    Mod(Box<Expr>, Box<Expr>),
    SMod(Box<Expr>, Box<Expr>),
    AddMod(Box<Expr>, Box<Expr>, Box<Expr>),
    MulMod(Box<Expr>, Box<Expr>, Box<Expr>),
    Exp(Box<Expr>, Box<Expr>),

    // Comparison
    Lt(Box<Expr>, Box<Expr>),
    Gt(Box<Expr>, Box<Expr>),
    SLt(Box<Expr>, Box<Expr>),
    SGt(Box<Expr>, Box<Expr>),
    Eq(Box<Expr>, Box<Expr>),
    IsZero(Box<Expr>),

    // Bitwise
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Xor(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    Shl(Box<Expr>, Box<Expr>),
    Shr(Box<Expr>, Box<Expr>),
    Sar(Box<Expr>, Box<Expr>),

    // Hashing
    Keccak256(Box<Expr>),

    // Storage
    SLoad(Box<Expr>),

    // Memory
    MLoad(Box<Expr>),

    // Environment
    Caller,
    CallValue,
    CallDataLoad(Box<Expr>),
    CallDataSize,
    Address,
    Balance(Box<Expr>),
    Origin,
    GasPrice,
    BlockHash(Box<Expr>),
    Coinbase,
    Timestamp,
    Number,
    GasLimit,
    ChainId,

    // Conditional
    Ite(Box<Prop>, Box<Expr>, Box<Expr>),
}

/// Proposition (boolean constraint for path conditions).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Prop {
    Bool(bool),
    IsTrue(Box<Expr>),
    IsZero(Box<Expr>),
    Eq(Box<Expr>, Box<Expr>),
    Lt(Box<Expr>, Box<Expr>),
    Gt(Box<Expr>, Box<Expr>),
    And(Box<Prop>, Box<Prop>),
    Or(Box<Prop>, Box<Prop>),
    Not(Box<Prop>),
}

/// A symbolic operation in a basic block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SymOp {
    Exec { opcode: Opcode },
    SStore { key: Expr, value: Expr },
    Call { gas: Expr, addr: Expr, value: Expr },
    DelegateCall { gas: Expr, addr: Expr },
    Log { topics: Vec<Expr>, data: Expr },
}

/// A basic block in the symbolic program.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymBlock {
    pub offset: usize,
    pub ops: Vec<SymOp>,
    pub terminator: Terminator,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Terminator {
    Stop,
    Return,
    Revert,
    Jump {
        target: usize,
    },
    JumpI {
        condition: Expr,
        target: usize,
        fallthrough: usize,
    },
    Invalid,
    SelfDestruct,
}

/// The full symbolic program extracted from bytecode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolicProgram {
    pub blocks: Vec<SymBlock>,
    pub entry: usize,
    pub jumpdests: Vec<usize>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expr_serde_roundtrip() {
        let expr = Expr::Add(
            Box::new(Expr::Var("x".into())),
            Box::new(Expr::Lit([0; 32])),
        );
        let json = serde_json::to_string(&expr).unwrap();
        let back: Expr = serde_json::from_str(&json).unwrap();
        assert_eq!(expr, back);
    }

    #[test]
    fn prop_serde_roundtrip() {
        let prop = Prop::And(
            Box::new(Prop::IsTrue(Box::new(Expr::Var("cond".into())))),
            Box::new(Prop::Lt(
                Box::new(Expr::Lit([0; 32])),
                Box::new(Expr::Var("x".into())),
            )),
        );
        let json = serde_json::to_string(&prop).unwrap();
        let back: Prop = serde_json::from_str(&json).unwrap();
        assert_eq!(prop, back);
    }

    #[test]
    fn program_construction() {
        let program = SymbolicProgram {
            blocks: vec![],
            entry: 0,
            jumpdests: vec![],
        };
        assert_eq!(program.blocks.len(), 0);
    }
}
