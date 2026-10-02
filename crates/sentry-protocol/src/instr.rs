//! Instruction set of the compiled protocol VM.
//!
//! Custom macros are inlined at compile time into straight-line
//! instruction tables executed by [`crate::engine`]. The default
//! validation path never touches a regex: only fields whose one-liner
//! declared the `regex` op carry an [`Instr::RegexOk`].

use std::sync::Arc;

use crate::ops::CharClass;
use crate::schema::{Decode, Endian};

/// Runtime value held in a VM register.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// Integer / boolean / bitfield register.
    Int(i64),
    /// Floating-point register (f32 widened to f64).
    Float(f64),
    /// Raw byte register (pre-decode).
    Bytes(Vec<u8>),
    /// Decoded string register.
    Str(String),
}

impl Default for Value {
    fn default() -> Self {
        Self::Int(0)
    }
}

impl Value {
    /// Integer view (bytes/strings report their length so `>N`/`<N` ops
    /// mean length on non-numeric values).
    pub fn as_num(&self) -> Option<i64> {
        match self {
            Self::Int(n) => Some(*n),
            Self::Float(f) => Some(*f as i64),
            Self::Bytes(b) => Some(b.len() as i64),
            Self::Str(s) => Some(s.len() as i64),
        }
    }

    /// Byte-slice view (strings included, for charset/regex checks).
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(b) => Some(b),
            Self::Str(s) => Some(s.as_bytes()),
            _ => None,
        }
    }
}

/// Binary arithmetic/bit operation of a `BinOp` instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOp {
    /// Bitwise AND.
    And,
    /// Bitwise OR.
    Or,
    /// Bitwise XOR.
    Xor,
    /// Shift left.
    Shl,
    /// Shift right.
    Shr,
    /// Addition.
    Add,
    /// Subtraction.
    Sub,
    /// Multiplication.
    Mul,
}

/// Operand of a binary op: register or immediate constant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operand {
    /// Register slot.
    Reg(u8),
    /// Immediate value.
    Const(i64),
}

/// Length-count semantics of the framing check (`check_len!`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LenCounts {
    /// The length field covers header + payload (bytes after the prefix).
    HeaderPlusData,
    /// The length field covers payload only; `header_size` is added.
    Data,
}

/// One VM instruction. Compiled per message; executed in order.
#[derive(Debug, Clone)]
pub enum Instr {
    /// Load a constant.
    Const {
        /// Destination register.
        dst: u8,
        /// Immediate value.
        value: i64,
    },
    /// Copy a register.
    Copy {
        /// Destination register.
        dst: u8,
        /// Source register.
        src: u8,
    },
    /// Read a fixed-size integer.
    ReadFixed {
        /// Destination register.
        dst: u8,
        /// Byte count (1/2/4/8).
        size: u8,
        /// Byte order.
        endian: Endian,
        /// Two's-complement interpretation.
        signed: bool,
    },
    /// Read a fixed-size float (widened to f64).
    ReadFloat {
        /// Destination register.
        dst: u8,
        /// Byte count (4 or 8).
        size: u8,
        /// Byte order.
        endian: Endian,
    },
    /// Read `len` bytes, length taken from a register.
    ReadBytes {
        /// Destination register.
        dst: u8,
        /// Register holding the byte count.
        len_reg: u8,
        /// Hard cap accepted from the register.
        max: u64,
    },
    /// Read until the terminator byte (consumed, excluded); fails at EOF.
    ReadUntil {
        /// Destination register.
        dst: u8,
        /// Terminator byte (consumed, excluded).
        term: u8,
        /// Hard cap on run length.
        max: u64,
    },
    /// Read `size` bytes without consuming them.
    Peek {
        /// Destination register.
        dst: u8,
        /// Byte count to peek.
        size: u8,
    },
    /// Decode raw bytes in place (`Bytes` → `Str`).
    Decode {
        /// Destination register.
        dst: u8,
        /// Source bytes register.
        src: u8,
        /// Byte transform.
        enc: Decode,
    },
    /// `dst = a OP b`.
    BinOp {
        /// Operation.
        op: BinOp,
        /// Destination register.
        dst: u8,
        /// Left operand.
        a: Operand,
        /// Right operand.
        b: Operand,
    },
    /// `dst = -src`.
    Neg {
        /// Destination register.
        dst: u8,
        /// Source register.
        src: u8,
    },
    /// Logical negation: `dst = (src == 0) ? 1 : 0`.
    Not {
        /// Destination register.
        dst: u8,
        /// Source register.
        src: u8,
    },
    /// Bounded loop: iterates `min(bound, cap)` times. A register bound
    /// must carry a compile-time `cap` (enforced by the compiler), so the
    /// iteration count is statically bounded.
    Loop {
        /// Iteration bound (register or constant).
        bound: Operand,
        /// Compile-time clamp for a register bound.
        cap: Option<u64>,
        /// Per-iteration instructions.
        body: Arc<[Instr]>,
    },
    /// Forward-only conditional skip: when `cond` evaluates to `0`, the
    /// next `skip` instructions are skipped (compiles an `if` block).
    /// There are no backward jumps, so programs always terminate.
    BranchIfZero {
        /// Condition operand (non-zero = run the block).
        cond: Operand,
        /// Number of instructions to skip when the condition is false.
        skip: u16,
    },
    /// `(reg & bits) == value` on an integer register.
    MaskOk {
        /// Register to check.
        reg: u8,
        /// AND mask.
        bits: u8,
        /// Required masked value.
        value: u8,
    },
    /// `min <= reg <= max`.
    RangeOk {
        /// Register to check.
        reg: u8,
        /// Inclusive lower bound.
        min: i64,
        /// Inclusive upper bound.
        max: i64,
    },
    /// `min <= len(reg) <= max` on bytes/string registers.
    LenOk {
        /// Register to check.
        reg: u8,
        /// Inclusive minimum length.
        min: u64,
        /// Inclusive maximum length.
        max: u64,
    },
    /// Framing check: length field must account for exactly this frame.
    CheckFrameLen {
        /// Register holding the declared length.
        len_reg: u8,
        /// Bytes skipped before the length field.
        offset: u8,
        /// Length-field byte count.
        prefix_size: u8,
        /// Byte order of the length field.
        endian: Endian,
        /// What the declared length covers.
        counts: LenCounts,
        /// Header size added for LenCounts::Data.
        header_size: u64,
        /// Cap on the declared length.
        max: u64,
    },
    /// Numeric value bound (or length bound on non-numeric registers).
    Gt {
        /// Register to check.
        reg: u8,
        /// Rejected upper bound (value must be strictly greater).
        n: i64,
    },
    /// Numeric value bound (or length bound on non-numeric registers).
    Lt {
        /// Register to check.
        reg: u8,
        /// Rejected lower bound (value must be strictly smaller).
        n: i64,
    },
    /// Length bound on bytes/string registers.
    LenGt {
        /// Register to check.
        reg: u8,
        /// Length must be strictly greater.
        n: u64,
    },
    /// Length bound on bytes/string registers.
    LenLt {
        /// Register to check.
        reg: u8,
        /// Length must be strictly smaller.
        n: u64,
    },
    /// Every byte must belong to the character class.
    CharsetOk {
        /// Register to check.
        reg: u8,
        /// Accepted character class.
        class: CharClass,
    },
    /// Regex match on the string form of the register.
    RegexOk {
        /// Register to check.
        reg: u8,
        /// Pattern compiled at schema load.
        re: Arc<regex::Regex>,
    },
    /// String value must be one of the listed values.
    InSet {
        /// Register to check.
        reg: u8,
        /// Allowed values.
        set: Arc<[String]>,
    },
    /// String value must not appear in the dataset.
    NotInSet {
        /// Register to check.
        reg: u8,
        /// Denied values.
        set: Arc<[String]>,
    },
    /// Program end.
    Halt,
}

/// Maximum VM registers per compiled protocol.
pub(crate) const MAX_REGS: usize = 16;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_views() {
        assert_eq!(Value::Int(7).as_num(), Some(7));
        assert_eq!(Value::Str("abcd".into()).as_num(), Some(4));
        assert_eq!(Value::Bytes(vec![1, 2, 3]).as_num(), Some(3));
        assert_eq!(Value::Float(2.9).as_num(), Some(2));
        assert!(Value::Str("hi".into()).as_bytes().is_some());
    }
}
