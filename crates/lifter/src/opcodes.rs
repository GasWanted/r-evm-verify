use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Opcode {
    Stop,
    Add,
    Mul,
    Sub,
    Div,
    SDiv,
    Mod,
    SMod,
    AddMod,
    MulMod,
    Exp,
    SignExtend,
    Lt,
    Gt,
    SLt,
    SGt,
    Eq,
    IsZero,
    And,
    Or,
    Xor,
    Not,
    Byte,
    Shl,
    Shr,
    Sar,
    Sha3,
    Address,
    Balance,
    Origin,
    Caller,
    CallValue,
    CallDataLoad,
    CallDataSize,
    CallDataCopy,
    CodeSize,
    CodeCopy,
    GasPrice,
    ExtCodeSize,
    ExtCodeCopy,
    ReturnDataSize,
    ReturnDataCopy,
    ExtCodeHash,
    BlockHash,
    Coinbase,
    Timestamp,
    Number,
    PrevRandao,
    GasLimit,
    ChainId,
    SelfBalance,
    BaseFee,
    Pop,
    MLoad,
    MStore,
    MStore8,
    SLoad,
    SStore,
    Jump,
    JumpI,
    Pc,
    MSize,
    Gas,
    JumpDest,
    Push(u8),
    Dup(u8),
    Swap(u8),
    Log(u8),
    Create,
    Call,
    CallCode,
    Return,
    DelegateCall,
    Create2,
    StaticCall,
    Revert,
    Invalid,
    SelfDestruct,
    Unknown(u8),
}

impl Opcode {
    pub fn from_byte(byte: u8) -> Self {
        match byte {
            0x00 => Self::Stop,
            0x01 => Self::Add,
            0x02 => Self::Mul,
            0x03 => Self::Sub,
            0x04 => Self::Div,
            0x05 => Self::SDiv,
            0x06 => Self::Mod,
            0x07 => Self::SMod,
            0x08 => Self::AddMod,
            0x09 => Self::MulMod,
            0x0A => Self::Exp,
            0x0B => Self::SignExtend,
            0x10 => Self::Lt,
            0x11 => Self::Gt,
            0x12 => Self::SLt,
            0x13 => Self::SGt,
            0x14 => Self::Eq,
            0x15 => Self::IsZero,
            0x16 => Self::And,
            0x17 => Self::Or,
            0x18 => Self::Xor,
            0x19 => Self::Not,
            0x1A => Self::Byte,
            0x1B => Self::Shl,
            0x1C => Self::Shr,
            0x1D => Self::Sar,
            0x20 => Self::Sha3,
            0x30 => Self::Address,
            0x31 => Self::Balance,
            0x32 => Self::Origin,
            0x33 => Self::Caller,
            0x34 => Self::CallValue,
            0x35 => Self::CallDataLoad,
            0x36 => Self::CallDataSize,
            0x37 => Self::CallDataCopy,
            0x38 => Self::CodeSize,
            0x39 => Self::CodeCopy,
            0x3A => Self::GasPrice,
            0x3B => Self::ExtCodeSize,
            0x3C => Self::ExtCodeCopy,
            0x3D => Self::ReturnDataSize,
            0x3E => Self::ReturnDataCopy,
            0x3F => Self::ExtCodeHash,
            0x40 => Self::BlockHash,
            0x41 => Self::Coinbase,
            0x42 => Self::Timestamp,
            0x43 => Self::Number,
            0x44 => Self::PrevRandao,
            0x45 => Self::GasLimit,
            0x46 => Self::ChainId,
            0x47 => Self::SelfBalance,
            0x48 => Self::BaseFee,
            0x50 => Self::Pop,
            0x51 => Self::MLoad,
            0x52 => Self::MStore,
            0x53 => Self::MStore8,
            0x54 => Self::SLoad,
            0x55 => Self::SStore,
            0x56 => Self::Jump,
            0x57 => Self::JumpI,
            0x58 => Self::Pc,
            0x59 => Self::MSize,
            0x5A => Self::Gas,
            0x5B => Self::JumpDest,
            0x60..=0x7F => Self::Push(byte - 0x60 + 1),
            0x80..=0x8F => Self::Dup(byte - 0x80 + 1),
            0x90..=0x9F => Self::Swap(byte - 0x90 + 1),
            0xA0..=0xA4 => Self::Log(byte - 0xA0),
            0xF0 => Self::Create,
            0xF1 => Self::Call,
            0xF2 => Self::CallCode,
            0xF3 => Self::Return,
            0xF4 => Self::DelegateCall,
            0xF5 => Self::Create2,
            0xFA => Self::StaticCall,
            0xFD => Self::Revert,
            0xFE => Self::Invalid,
            0xFF => Self::SelfDestruct,
            b => Self::Unknown(b),
        }
    }

    /// Number of immediate bytes following this opcode.
    pub fn immediate_size(&self) -> usize {
        match self {
            Self::Push(n) => *n as usize,
            _ => 0,
        }
    }

    /// True if this opcode terminates a basic block.
    pub fn is_terminator(&self) -> bool {
        matches!(
            self,
            Self::Jump
                | Self::JumpI
                | Self::Stop
                | Self::Return
                | Self::Revert
                | Self::Invalid
                | Self::SelfDestruct
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_push1() {
        let op = Opcode::from_byte(0x60);
        assert_eq!(op, Opcode::Push(1));
        assert_eq!(op.immediate_size(), 1);
    }

    #[test]
    fn decode_push32() {
        let op = Opcode::from_byte(0x7F);
        assert_eq!(op, Opcode::Push(32));
        assert_eq!(op.immediate_size(), 32);
    }

    #[test]
    fn decode_add() {
        let op = Opcode::from_byte(0x01);
        assert_eq!(op, Opcode::Add);
        assert_eq!(op.immediate_size(), 0);
    }

    #[test]
    fn decode_dup_swap() {
        assert_eq!(Opcode::from_byte(0x80), Opcode::Dup(1));
        assert_eq!(Opcode::from_byte(0x8F), Opcode::Dup(16));
        assert_eq!(Opcode::from_byte(0x90), Opcode::Swap(1));
        assert_eq!(Opcode::from_byte(0x9F), Opcode::Swap(16));
    }

    #[test]
    fn decode_unknown() {
        let op = Opcode::from_byte(0xEF);
        assert_eq!(op, Opcode::Unknown(0xEF));
    }

    #[test]
    fn terminators() {
        assert!(Opcode::Jump.is_terminator());
        assert!(Opcode::JumpI.is_terminator());
        assert!(Opcode::Stop.is_terminator());
        assert!(Opcode::Return.is_terminator());
        assert!(Opcode::Revert.is_terminator());
        assert!(!Opcode::Add.is_terminator());
        assert!(!Opcode::Push(1).is_terminator());
    }
}
