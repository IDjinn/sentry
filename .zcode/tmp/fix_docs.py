import io

# instr.rs: expand single-line enum fields into documented multi-line form
p = 'crates/sentry-protocol/src/instr.rs'
s = open(p, encoding='utf-8').read()
s = s.replace("""pub enum Instr {
    /// Load a constant.
    Const { dst: u8, value: i64 },
    /// Copy a register.
    Copy { dst: u8, src: u8 },""",
"""pub enum Instr {
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
    },""")
s = s.replace("""    ReadFixed {
        dst: u8,
        size: u8,
        endian: Endian,
        signed: bool,
    },""",
"""    ReadFixed {
        /// Destination register.
        dst: u8,
        /// Byte count (1/2/4/8).
        size: u8,
        /// Byte order.
        endian: Endian,
        /// Two's-complement interpretation.
        signed: bool,
    },""")
s = s.replace("""    ReadFloat { dst: u8, size: u8, endian: Endian },""",
"""    ReadFloat {
        /// Destination register.
        dst: u8,
        /// Byte count (4 or 8).
        size: u8,
        /// Byte order.
        endian: Endian,
    },""")
s = s.replace("""    ReadBytes { dst: u8, len_reg: u8, max: u64 },""",
"""    ReadBytes {
        /// Destination register.
        dst: u8,
        /// Register holding the byte count.
        len_reg: u8,
        /// Hard cap accepted from the register.
        max: u64,
    },""")
s = s.replace("""    ReadUntil { dst: u8, term: u8, max: u64 },""",
"""    ReadUntil {
        /// Destination register.
        dst: u8,
        /// Terminator byte (consumed, excluded).
        term: u8,
        /// Hard cap on run length.
        max: u64,
    },""")
s = s.replace("""    Peek { dst: u8, size: u8 },""",
"""    Peek {
        /// Destination register.
        dst: u8,
        /// Byte count to peek.
        size: u8,
    },""")
s = s.replace("""    Decode { dst: u8, src: u8, enc: Decode },""",
"""    Decode {
        /// Destination register.
        dst: u8,
        /// Source bytes register.
        src: u8,
        /// Byte transform.
        enc: Decode,
    },""")
s = s.replace("""    BinOp { op: BinOp, dst: u8, a: Operand, b: Operand },""",
"""    BinOp {
        /// Operation.
        op: BinOp,
        /// Destination register.
        dst: u8,
        /// Left operand.
        a: Operand,
        /// Right operand.
        b: Operand,
    },""")
s = s.replace("""    Neg { dst: u8, src: u8 },""",
"""    Neg {
        /// Destination register.
        dst: u8,
        /// Source register.
        src: u8,
    },""")
s = s.replace("""    NegIf { dst: u8, src: u8, flag: u8 },""",
"""    NegIf {
        /// Destination register.
        dst: u8,
        /// Source register.
        src: u8,
        /// Flag register (non-zero negates).
        flag: u8,
    },""")
s = s.replace("""    Repeat {
        times_reg: u8,
        max: u64,
        body: Arc<[Instr]>,
    },""",
"""    Repeat {
        /// Register holding the iteration count.
        times_reg: u8,
        /// Runtime cap; exceeding it is a violation.
        max: u64,
        /// Per-iteration instructions.
        body: Arc<[Instr]>,
    },""")
s = s.replace("""    MaskOk { reg: u8, bits: u8, value: u8 },""",
"""    MaskOk {
        /// Register to check.
        reg: u8,
        /// AND mask.
        bits: u8,
        /// Required masked value.
        value: u8,
    },""")
s = s.replace("""    RangeOk { reg: u8, min: i64, max: i64 },""",
"""    RangeOk {
        /// Register to check.
        reg: u8,
        /// Inclusive lower bound.
        min: i64,
        /// Inclusive upper bound.
        max: i64,
    },""")
s = s.replace("""    LenOk { reg: u8, min: u64, max: u64 },""",
"""    LenOk {
        /// Register to check.
        reg: u8,
        /// Inclusive minimum length.
        min: u64,
        /// Inclusive maximum length.
        max: u64,
    },""")
s = s.replace("""    CheckFrameLen {
        len_reg: u8,
        offset: u8,
        prefix_size: u8,
        endian: Endian,
        counts: LenCounts,
        header_size: u64,
        max: u64,
    },""",
"""    CheckFrameLen {
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
    },""")
s = s.replace("""    /// Numeric value bound (or length bound on non-numeric registers).
    Gt { reg: u8, n: i64 },
    /// Numeric value bound (or length bound on non-numeric registers).
    Lt { reg: u8, n: i64 },""",
"""    /// Numeric value bound (or length bound on non-numeric registers).
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
    },""")
s = s.replace("""    /// Length bound on bytes/string registers.
    LenGt { reg: u8, n: u64 },
    /// Length bound on bytes/string registers.
    LenLt { reg: u8, n: u64 },""",
"""    /// Length bound on bytes/string registers.
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
    },""")
s = s.replace("""    /// Every byte must belong to the character class.
    CharsetOk { reg: u8, class: CharClass },
    /// Regex match on the string form of the register.
    RegexOk { reg: u8, re: Arc<regex::Regex> },
    /// String value must be one of the listed values.
    InSet { reg: u8, set: Arc<[String]> },
    /// String value must not appear in the dataset.
    NotInSet { reg: u8, set: Arc<[String]> },""",
"""    /// Every byte must belong to the character class.
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
    },""")
open(p, 'w', encoding='utf-8', newline='\n').write(s)

# compile.rs: drop dead `key` field on Dispatch::Int
p = 'crates/sentry-protocol/src/compile.rs'
s = open(p, encoding='utf-8').read()
s = s.replace("""enum Dispatch {
    Int { key: String, reg: u8, table: HashMap<i64, u16> },""",
"""enum Dispatch {
    Int { reg: u8, table: HashMap<i64, u16> },""")
s = s.replace("""        if dispatch_table.is_empty() {
            Dispatch::Linear(linear)
        } else {
            Dispatch::Int { key, reg, table: dispatch_table }
        }""", """        if dispatch_table.is_empty() {
            Dispatch::Linear(linear)
        } else {
            let _ = key;
            Dispatch::Int { reg, table: dispatch_table }
        }""")
open(p, 'w', encoding='utf-8', newline='\n').write(s)
print("done")
