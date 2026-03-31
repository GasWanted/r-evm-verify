use crate::disasm::{disassemble, Instruction};
use crate::opcodes::Opcode;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicBlock {
    /// Byte offset of the first instruction.
    pub start: usize,
    pub instructions: Vec<Instruction>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EdgeKind {
    Jump,
    Fallthrough,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Edge {
    pub from: usize,
    pub to: usize,
    pub kind: EdgeKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cfg {
    /// Basic blocks keyed by their start offset.
    pub blocks: BTreeMap<usize, BasicBlock>,
    pub edges: Vec<Edge>,
}

/// Build a control flow graph from raw EVM bytecode.
pub fn build_cfg(bytecode: &[u8]) -> Cfg {
    let instructions = disassemble(bytecode);
    if instructions.is_empty() {
        return Cfg {
            blocks: BTreeMap::new(),
            edges: Vec::new(),
        };
    }

    // Collect all JUMPDEST offsets for validation.
    let jumpdests: HashSet<usize> = instructions
        .iter()
        .filter(|i| i.opcode == Opcode::JumpDest)
        .map(|i| i.offset)
        .collect();

    // Identify block start offsets.
    let mut block_starts: BTreeSet<usize> = BTreeSet::new();
    block_starts.insert(0);

    for (idx, instr) in instructions.iter().enumerate() {
        if instr.opcode == Opcode::JumpDest {
            block_starts.insert(instr.offset);
        }
        if instr.opcode.is_terminator() {
            if let Some(next) = instructions.get(idx + 1) {
                block_starts.insert(next.offset);
            }
        }
    }

    // Build blocks.
    let starts_vec: Vec<usize> = block_starts.iter().copied().collect();
    let mut blocks = BTreeMap::new();

    for (i, &start) in starts_vec.iter().enumerate() {
        let next_start = starts_vec.get(i + 1).copied().unwrap_or(usize::MAX);
        let block_instrs: Vec<Instruction> = instructions
            .iter()
            .filter(|instr| instr.offset >= start && instr.offset < next_start)
            .cloned()
            .collect();
        if !block_instrs.is_empty() {
            blocks.insert(
                start,
                BasicBlock {
                    start,
                    instructions: block_instrs,
                },
            );
        }
    }

    // Build edges.
    let mut edges = Vec::new();
    for block in blocks.values() {
        let last = match block.instructions.last() {
            Some(i) => i,
            None => continue,
        };

        match last.opcode {
            Opcode::Jump => {
                if block.instructions.len() >= 2 {
                    let prev = &block.instructions[block.instructions.len() - 2];
                    if let Opcode::Push(_) = prev.opcode {
                        let target = push_value(&prev.immediate);
                        if jumpdests.contains(&target) {
                            edges.push(Edge {
                                from: block.start,
                                to: target,
                                kind: EdgeKind::Jump,
                            });
                        }
                    }
                }
            }
            Opcode::JumpI => {
                // Fallthrough edge (condition false).
                let fallthrough = last.offset + 1;
                if blocks.contains_key(&fallthrough) {
                    edges.push(Edge {
                        from: block.start,
                        to: fallthrough,
                        kind: EdgeKind::Fallthrough,
                    });
                }
                // Jump edge (condition true).
                // JUMPI pops dest from top of stack. In the common pattern
                // (condition, PUSH dest, JUMPI), dest is instructions[len-2].
                if block.instructions.len() >= 2 {
                    let dest_instr = &block.instructions[block.instructions.len() - 2];
                    if let Opcode::Push(_) = dest_instr.opcode {
                        let target = push_value(&dest_instr.immediate);
                        if jumpdests.contains(&target) {
                            edges.push(Edge {
                                from: block.start,
                                to: target,
                                kind: EdgeKind::Jump,
                            });
                        }
                    }
                }
            }
            Opcode::Stop
            | Opcode::Return
            | Opcode::Revert
            | Opcode::Invalid
            | Opcode::SelfDestruct => {
                // Terminal — no outgoing edges.
            }
            _ => {
                let next_offset = last.offset + 1 + last.opcode.immediate_size();
                if blocks.contains_key(&next_offset) {
                    edges.push(Edge {
                        from: block.start,
                        to: next_offset,
                        kind: EdgeKind::Fallthrough,
                    });
                }
            }
        }
    }

    Cfg { blocks, edges }
}

fn push_value(bytes: &[u8]) -> usize {
    let mut val: usize = 0;
    for &b in bytes {
        val = (val << 8) | (b as usize);
    }
    val
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linear_block() {
        let bytecode = vec![0x60, 0x05, 0x60, 0x03, 0x01, 0x00];
        let cfg = build_cfg(&bytecode);
        assert_eq!(cfg.blocks.len(), 1);
        assert_eq!(cfg.blocks[&0].instructions.len(), 4);
        assert!(cfg.edges.is_empty());
    }

    #[test]
    fn conditional_branch() {
        // EVM JUMPI: pops dest (top), then condition (second).
        // Pattern: PUSH condition, PUSH dest, JUMPI
        let bytecode = vec![
            0x60, 0x01, // PUSH1 0x01 (condition = true)
            0x60, 0x08, // PUSH1 0x08 (dest = offset 8)
            0x57, // JUMPI
            0x60, 0x00, // PUSH1 0x00
            0x00, // STOP
            0x5B, // JUMPDEST at offset 8
            0x60, 0x01, // PUSH1 0x01
            0x00, // STOP
        ];
        let cfg = build_cfg(&bytecode);
        assert_eq!(cfg.blocks.len(), 3);
        assert!(cfg.blocks.contains_key(&0));
        assert!(cfg.blocks.contains_key(&5));
        assert!(cfg.blocks.contains_key(&8));
        assert_eq!(cfg.edges.len(), 2);
    }

    #[test]
    fn unconditional_jump() {
        let bytecode = vec![
            0x60, 0x04, // PUSH1 0x04
            0x56, // JUMP
            0x00, // STOP (unreachable)
            0x5B, // JUMPDEST at offset 4
            0x00, // STOP
        ];
        let cfg = build_cfg(&bytecode);
        assert_eq!(cfg.blocks.len(), 3);
        let jump_edges: Vec<_> = cfg
            .edges
            .iter()
            .filter(|e| e.kind == EdgeKind::Jump)
            .collect();
        assert_eq!(jump_edges.len(), 1);
        assert_eq!(jump_edges[0].from, 0);
        assert_eq!(jump_edges[0].to, 4);
    }
}
