use crate::opcodes::Opcode;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Instruction {
    /// Byte offset in the original bytecode.
    pub offset: usize,
    pub opcode: Opcode,
    /// Immediate data bytes (empty for non-PUSH opcodes).
    pub immediate: Vec<u8>,
}

/// Disassemble raw EVM bytecode into a list of instructions.
pub fn disassemble(bytecode: &[u8]) -> Vec<Instruction> {
    let mut instructions = Vec::new();
    let mut pc = 0;

    while pc < bytecode.len() {
        let opcode = Opcode::from_byte(bytecode[pc]);
        let imm_size = opcode.immediate_size();
        let available = (bytecode.len() - pc - 1).min(imm_size);
        let immediate = bytecode[pc + 1..pc + 1 + available].to_vec();

        instructions.push(Instruction {
            offset: pc,
            opcode,
            immediate,
        });

        pc += 1 + imm_size;
    }

    instructions
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disassemble_push1_add_stop() {
        let bytecode = vec![0x60, 0x05, 0x60, 0x03, 0x01, 0x00];
        let instructions = disassemble(&bytecode);
        assert_eq!(instructions.len(), 4);
        assert_eq!(instructions[0].offset, 0);
        assert_eq!(instructions[0].opcode, Opcode::Push(1));
        assert_eq!(instructions[0].immediate, vec![0x05]);
        assert_eq!(instructions[1].offset, 2);
        assert_eq!(instructions[1].opcode, Opcode::Push(1));
        assert_eq!(instructions[1].immediate, vec![0x03]);
        assert_eq!(instructions[2].offset, 4);
        assert_eq!(instructions[2].opcode, Opcode::Add);
        assert_eq!(instructions[3].offset, 5);
        assert_eq!(instructions[3].opcode, Opcode::Stop);
    }

    #[test]
    fn disassemble_truncated_push() {
        let bytecode = vec![0x61, 0xAB];
        let instructions = disassemble(&bytecode);
        assert_eq!(instructions.len(), 1);
        assert_eq!(instructions[0].opcode, Opcode::Push(2));
        assert_eq!(instructions[0].immediate, vec![0xAB]);
    }
}
