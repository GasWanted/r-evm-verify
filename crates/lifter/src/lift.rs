use crate::cfg::{build_cfg, Cfg, EdgeKind};
use crate::disasm::Instruction;
use crate::ir::*;
use crate::opcodes::Opcode;
/// Lift raw EVM bytecode into a SymbolicProgram.
pub fn lift(bytecode: &[u8]) -> SymbolicProgram {
    let cfg = build_cfg(bytecode);
    lift_cfg(&cfg)
}

/// Lift a pre-built CFG into a SymbolicProgram.
pub fn lift_cfg(cfg: &Cfg) -> SymbolicProgram {
    let jumpdests: Vec<usize> = cfg
        .blocks
        .keys()
        .copied()
        .filter(|offset| {
            cfg.blocks
                .get(offset)
                .and_then(|b| b.instructions.first())
                .map(|i| i.opcode == Opcode::JumpDest)
                .unwrap_or(false)
        })
        .collect();

    let blocks: Vec<SymBlock> = cfg
        .blocks
        .values()
        .map(|block| lift_block(block, cfg))
        .collect();

    let entry = cfg.blocks.keys().next().copied().unwrap_or(0);

    SymbolicProgram {
        blocks,
        entry,
        jumpdests,
    }
}

fn lift_block(block: &crate::cfg::BasicBlock, cfg: &Cfg) -> SymBlock {
    let mut ops = Vec::new();
    let instructions = &block.instructions;
    let last = instructions.last();

    for instr in instructions {
        if instr.opcode.is_terminator() {
            // Handled as the block terminator below.
            continue;
        }
        if instr.opcode == Opcode::JumpDest {
            // Metadata-only, no symbolic operation.
            continue;
        }
        if let Some(op) = classify_instruction(instr) {
            ops.push(op);
        }
    }

    let terminator = match last.map(|i| &i.opcode) {
        Some(Opcode::Stop) => Terminator::Stop,
        Some(Opcode::Return) => Terminator::Return,
        Some(Opcode::Revert) => Terminator::Revert,
        Some(Opcode::Invalid) => Terminator::Invalid,
        Some(Opcode::SelfDestruct) => Terminator::SelfDestruct,
        Some(Opcode::Jump) => {
            // Resolve static jump target from edges.
            let target = cfg
                .edges
                .iter()
                .find(|e| e.from == block.start && e.kind == EdgeKind::Jump)
                .map(|e| e.to)
                .unwrap_or(0);
            Terminator::Jump { target }
        }
        Some(Opcode::JumpI) => {
            let target = cfg
                .edges
                .iter()
                .find(|e| e.from == block.start && e.kind == EdgeKind::Jump)
                .map(|e| e.to)
                .unwrap_or(0);
            let fallthrough = cfg
                .edges
                .iter()
                .find(|e| e.from == block.start && e.kind == EdgeKind::Fallthrough)
                .map(|e| e.to)
                .unwrap_or(0);
            // The condition is symbolic — we represent it as a variable
            // keyed on the JUMPI's offset.
            let condition = Expr::Var(format!("cond@{}", last.unwrap().offset));
            Terminator::JumpI {
                condition,
                target,
                fallthrough,
            }
        }
        _ => {
            // Block doesn't end with a terminator (falls through).
            let fallthrough = cfg
                .edges
                .iter()
                .find(|e| e.from == block.start && e.kind == EdgeKind::Fallthrough)
                .map(|e| e.to)
                .unwrap_or(0);
            Terminator::Jump {
                target: fallthrough,
            }
        }
    };

    SymBlock {
        offset: block.start,
        ops,
        terminator,
    }
}

/// Classify a non-terminator instruction into a SymOp.
fn classify_instruction(instr: &Instruction) -> Option<SymOp> {
    match instr.opcode {
        // Storage write
        Opcode::SStore => Some(SymOp::SStore {
            key: Expr::Var(format!("stack_0@{}", instr.offset)),
            value: Expr::Var(format!("stack_1@{}", instr.offset)),
        }),

        // External calls
        Opcode::Call => Some(SymOp::Call {
            gas: Expr::Var(format!("stack_0@{}", instr.offset)),
            addr: Expr::Var(format!("stack_1@{}", instr.offset)),
            value: Expr::Var(format!("stack_2@{}", instr.offset)),
        }),
        Opcode::DelegateCall => Some(SymOp::DelegateCall {
            gas: Expr::Var(format!("stack_0@{}", instr.offset)),
            addr: Expr::Var(format!("stack_1@{}", instr.offset)),
        }),
        Opcode::StaticCall => Some(SymOp::Call {
            gas: Expr::Var(format!("stack_0@{}", instr.offset)),
            addr: Expr::Var(format!("stack_1@{}", instr.offset)),
            value: Expr::Lit([0; 32]), // staticcall has no value transfer
        }),
        Opcode::CallCode => Some(SymOp::Call {
            gas: Expr::Var(format!("stack_0@{}", instr.offset)),
            addr: Expr::Var(format!("stack_1@{}", instr.offset)),
            value: Expr::Var(format!("stack_2@{}", instr.offset)),
        }),

        // Logging
        Opcode::Log(n) => {
            let topics = (0..n)
                .map(|i| Expr::Var(format!("topic_{}@{}", i, instr.offset)))
                .collect();
            Some(SymOp::Log {
                topics,
                data: Expr::Var(format!("log_data@{}", instr.offset)),
            })
        }

        // All other opcodes get the generic Exec wrapper
        Opcode::Add
        | Opcode::Mul
        | Opcode::Sub
        | Opcode::Div
        | Opcode::SDiv
        | Opcode::Mod
        | Opcode::SMod
        | Opcode::AddMod
        | Opcode::MulMod
        | Opcode::Exp
        | Opcode::SignExtend
        | Opcode::Lt
        | Opcode::Gt
        | Opcode::SLt
        | Opcode::SGt
        | Opcode::Eq
        | Opcode::IsZero
        | Opcode::And
        | Opcode::Or
        | Opcode::Xor
        | Opcode::Not
        | Opcode::Byte
        | Opcode::Shl
        | Opcode::Shr
        | Opcode::Sar
        | Opcode::Sha3
        | Opcode::SLoad
        | Opcode::MLoad
        | Opcode::MStore
        | Opcode::MStore8
        | Opcode::CallDataLoad
        | Opcode::CallDataSize
        | Opcode::CallDataCopy
        | Opcode::Address
        | Opcode::Balance
        | Opcode::Origin
        | Opcode::Caller
        | Opcode::CallValue
        | Opcode::CodeSize
        | Opcode::CodeCopy
        | Opcode::GasPrice
        | Opcode::ExtCodeSize
        | Opcode::ExtCodeCopy
        | Opcode::ReturnDataSize
        | Opcode::ReturnDataCopy
        | Opcode::ExtCodeHash
        | Opcode::BlockHash
        | Opcode::Coinbase
        | Opcode::Timestamp
        | Opcode::Number
        | Opcode::PrevRandao
        | Opcode::GasLimit
        | Opcode::ChainId
        | Opcode::SelfBalance
        | Opcode::BaseFee
        | Opcode::Create
        | Opcode::Create2 => Some(SymOp::Exec {
            opcode: instr.opcode,
        }),

        // Stack/control ops that don't produce meaningful symbolic operations
        Opcode::Pop
        | Opcode::Push(_)
        | Opcode::Dup(_)
        | Opcode::Swap(_)
        | Opcode::Pc
        | Opcode::MSize
        | Opcode::Gas => None,

        // Terminators and JumpDest handled elsewhere
        Opcode::Stop
        | Opcode::Return
        | Opcode::Revert
        | Opcode::Invalid
        | Opcode::SelfDestruct
        | Opcode::Jump
        | Opcode::JumpI
        | Opcode::JumpDest => None,

        Opcode::Unknown(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lift_trivial_stop() {
        // PUSH1 0x00 STOP
        let program = lift(&[0x60, 0x00, 0x00]);
        assert_eq!(program.blocks.len(), 1);
        assert_eq!(program.entry, 0);
        assert!(matches!(program.blocks[0].terminator, Terminator::Stop));
    }

    #[test]
    fn lift_arithmetic_block() {
        // PUSH1 1 PUSH1 2 ADD PUSH1 0 SSTORE STOP
        let program = lift(&[0x60, 0x01, 0x60, 0x02, 0x01, 0x60, 0x00, 0x55, 0x00]);
        assert_eq!(program.blocks.len(), 1);
        let block = &program.blocks[0];

        // Should have: ADD (Exec), SSTORE (SStore)
        let exec_count = block
            .ops
            .iter()
            .filter(|op| matches!(op, SymOp::Exec { .. }))
            .count();
        let sstore_count = block
            .ops
            .iter()
            .filter(|op| matches!(op, SymOp::SStore { .. }))
            .count();
        assert_eq!(exec_count, 1); // ADD
        assert_eq!(sstore_count, 1); // SSTORE
    }

    #[test]
    fn lift_call_detected() {
        // 6x PUSH1 0x00 + PUSH1 addr + CALL + STOP
        let bytecode = vec![
            0x60, 0x00, // PUSH1 0 (retSize)
            0x60, 0x00, // PUSH1 0 (retOffset)
            0x60, 0x00, // PUSH1 0 (argsSize)
            0x60, 0x00, // PUSH1 0 (argsOffset)
            0x60, 0x00, // PUSH1 0 (value)
            0x60, 0x0a, // PUSH1 0x0a (addr)
            0x60, 0xff, // PUSH1 0xff (gas)
            0xF1, // CALL
            0x00, // STOP
        ];
        let program = lift(&bytecode);
        let block = &program.blocks[0];
        let call_ops: Vec<_> = block
            .ops
            .iter()
            .filter(|op| matches!(op, SymOp::Call { .. }))
            .collect();
        assert_eq!(call_ops.len(), 1);
    }

    #[test]
    fn lift_conditional_branch() {
        // PUSH1 0x01 (cond) PUSH1 0x08 (dest) JUMPI | PUSH1 0x00 STOP | JUMPDEST PUSH1 0x01 STOP
        let bytecode = vec![
            0x60, 0x01, 0x60, 0x08, 0x57, 0x60, 0x00, 0x00, 0x5B, 0x60, 0x01, 0x00,
        ];
        let program = lift(&bytecode);
        assert_eq!(program.blocks.len(), 3);

        // First block should have JumpI terminator
        let entry_block = program.blocks.iter().find(|b| b.offset == 0).unwrap();
        assert!(matches!(
            entry_block.terminator,
            Terminator::JumpI {
                target: 8,
                fallthrough: 5,
                ..
            }
        ));

        // Jump target should be in jumpdests
        assert!(program.jumpdests.contains(&8));
    }

    #[test]
    fn lift_sstore_classified() {
        // PUSH1 0x42 PUSH1 0x00 SSTORE STOP
        let program = lift(&[0x60, 0x42, 0x60, 0x00, 0x55, 0x00]);
        let block = &program.blocks[0];
        let has_sstore = block
            .ops
            .iter()
            .any(|op| matches!(op, SymOp::SStore { .. }));
        assert!(has_sstore);
    }

    #[test]
    fn lift_delegate_call_classified() {
        // Minimal DELEGATECALL: 6x PUSH + F4 + STOP
        let bytecode = vec![
            0x60, 0x00, // retSize
            0x60, 0x00, // retOffset
            0x60, 0x00, // argsSize
            0x60, 0x00, // argsOffset
            0x60, 0x0a, // addr
            0x60, 0xff, // gas
            0xF4, // DELEGATECALL
            0x00, // STOP
        ];
        let program = lift(&bytecode);
        let block = &program.blocks[0];
        let has_delegatecall = block
            .ops
            .iter()
            .any(|op| matches!(op, SymOp::DelegateCall { .. }));
        assert!(has_delegatecall);
    }

    #[test]
    fn lift_log_classified() {
        // PUSH1 0 PUSH1 0 PUSH1 0 LOG1 STOP
        let bytecode = vec![0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0xA1, 0x00];
        let program = lift(&bytecode);
        let block = &program.blocks[0];
        let log_ops: Vec<_> = block
            .ops
            .iter()
            .filter(|op| matches!(op, SymOp::Log { .. }))
            .collect();
        assert_eq!(log_ops.len(), 1);
        if let SymOp::Log { topics, .. } = &log_ops[0] {
            assert_eq!(topics.len(), 1); // LOG1 has 1 topic
        }
    }

    #[test]
    fn lift_revert_terminator() {
        // PUSH1 0 PUSH1 0 REVERT
        let program = lift(&[0x60, 0x00, 0x60, 0x00, 0xFD]);
        assert!(matches!(program.blocks[0].terminator, Terminator::Revert));
    }

    #[test]
    fn lift_empty_bytecode() {
        let program = lift(&[]);
        assert!(program.blocks.is_empty());
        assert_eq!(program.entry, 0);
    }
}
