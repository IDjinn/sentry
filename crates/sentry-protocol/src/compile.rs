//! Compiler: schema → instruction tables.
//!
//! Custom macros declared in `types:` are inlined here. Sugar forms are
//! desugared to register-machine steps and expanded into the same flat
//! [`Instr`] sequence the VM executes — a protocol-specific macro costs
//! exactly what a hand-written instruction sequence would cost.
//!
//! Compilation is bounded: register count, per-message instruction count
//! and loop caps are all capped so a hostile schema cannot exhaust the
//! compiler (schemas are shareable artifacts). `while` bounds must be
//! statically provable (constant or `min!(expr, cap)`); `if` blocks
//! compile to forward-only conditional skips, so programs always
//! terminate.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use crate::error::ProtocolError;
use crate::expr::{is_reserved, Expr};
use crate::instr::{BinOp, Instr, LenCounts, Operand, Value, MAX_REGS};
use crate::ops::{tokenize, FieldOp};
use crate::schema::{
    Decode, Endian, Keepalive, MaskOk, MessageDef, Mode, OnRepeat, ProtocolSchema, Step, SugarRead,
    TypeDef, WhenValue,
};
use crate::steps::{arg_int, arg_str, parse_int_literal, ParsedStatement, RunStep};
use crate::{Violation, MAX_INSTRS_PER_MESSAGE, MAX_TYPE_DEPTH};

/// Host-provided datasets (`not_in` targets), by name.
#[derive(Debug, Clone, Default)]
pub struct CompileOptions {
    /// Dataset entries available to `not_in` ops.
    pub datasets: HashMap<String, Arc<[String]>>,
}

/// A fully compiled schema set, hot-swappable as one [`Arc`] per reload.
#[derive(Debug, Default)]
pub struct Compiled {
    /// One compiled protocol per schema file.
    pub protocols: Vec<CompiledProtocol>,
    /// Port → protocol index (first schema claiming the port wins).
    by_port: HashMap<u16, usize>,
}

impl Compiled {
    /// Compiles `schema` and appends it to the set.
    pub fn add(
        &mut self,
        schema: ProtocolSchema,
        opts: &CompileOptions,
    ) -> Result<(), ProtocolError> {
        let proto = compile_schema(schema, opts)?;
        for port in proto.ports.clone() {
            self.by_port.entry(port).or_insert(self.protocols.len());
        }
        self.protocols.push(proto);
        Ok(())
    }

    /// The protocol guarding `port`, if any.
    pub fn for_port(&self, port: u16) -> Option<&CompiledProtocol> {
        self.protocols.get(*self.by_port.get(&port)?)
    }
}

/// Framing metadata captured from `check_len!` (the host uses it to split
/// a TCP stream into frames before calling the engine).
#[derive(Debug, Clone, Copy)]
pub struct FrameSpec {
    /// Bytes skipped before the length field.
    pub offset: u8,
    /// Length-field byte count.
    pub prefix_size: u8,
    /// Byte order of the length field.
    pub endian: Endian,
    /// What the declared length covers.
    pub counts: LenCounts,
    /// Header size added for [`LenCounts::Data`].
    pub header_size: u64,
    /// Cap on the declared length.
    pub max: u64,
}

/// One compiled protocol schema.
#[derive(Debug)]
pub struct CompiledProtocol {
    /// Schema `id` (violation label).
    pub schema_id: Arc<str>,
    /// Enforcement posture.
    pub mode: Mode,
    /// Ports claimed by `transport`.
    pub ports: Vec<u16>,
    /// Framing split info from `check_len!`, if the schema declared it.
    pub framing: Option<FrameSpec>,
    /// Pipeline run before dispatch on every frame.
    pub preamble: Vec<Instr>,
    /// Message programs, in schema order.
    pub messages: Vec<MessageProgram>,
    /// Dispatch structure built from the union of `when` maps.
    dispatch: Dispatch,
    /// Policies by name.
    pub policies: HashMap<String, PolicySpec>,
    /// Policy applied to framing failures / unknown headers.
    pub unknown_policy: Arc<str>,
    /// Register holding the primary dispatch variable (for diagnostics).
    pub dispatch_reg: Option<u8>,
}

/// Severity spec of a named policy.
#[derive(Debug, Clone)]
pub struct PolicySpec {
    /// Signal weight on violation.
    pub weight: u8,
    /// Repeat-escalation window, if declared.
    pub on_repeat: Option<OnRepeat>,
}

/// One compiled message.
#[derive(Debug)]
pub struct MessageProgram {
    /// Message label (from the YAML key).
    pub name: Arc<str>,
    /// Stable hash of the name (connection `after` bookkeeping).
    pub name_hash: u64,
    /// Policy cited on violations.
    pub policy: Arc<str>,
    /// Hashes of messages that must appear first.
    pub after: Vec<u64>,
    /// Liveness semantics.
    pub keepalive: Option<Keepalive>,
    /// Straight-line validation program.
    pub program: Vec<Instr>,
}

#[derive(Debug)]
enum Dispatch {
    Int { reg: u8, table: HashMap<i64, u16> },
    Linear(Vec<(Vec<WhenCond>, u16)>),
}

#[derive(Debug)]
struct WhenCond {
    reg: u8,
    values: WhenSet,
}

#[derive(Debug)]
enum WhenSet {
    Int(Vec<i64>),
    Str(Vec<String>),
}

impl WhenSet {
    fn contains(&self, v: &Value) -> bool {
        match (self, v) {
            (Self::Int(xs), Value::Int(n)) => xs.contains(n),
            (Self::Int(_), Value::Float(f)) => xs_contains_f64(self, *f),
            (Self::Str(xs), Value::Str(s)) => xs.iter().any(|x| x == s),
            (Self::Str(xs), Value::Int(n)) => xs.iter().any(|x| x == &n.to_string()),
            (Self::Str(xs), Value::Bytes(b)) => {
                let s = String::from_utf8_lossy(b);
                xs.iter().any(|x| x == &s)
            }
            _ => false,
        }
    }
}

fn xs_contains_f64(set: &WhenSet, f: f64) -> bool {
    match set {
        WhenSet::Int(xs) => xs.iter().any(|x| *x as f64 == f),
        WhenSet::Str(_) => false,
    }
}

/// Stable per-process hash for message names (fixed-key SipHash).
pub(crate) fn name_hash(name: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    name.hash(&mut h);
    h.finish()
}

struct Ctx<'a> {
    schema: &'a ProtocolSchema,
    opts: &'a CompileOptions,
    regs: BTreeMap<String, u8>,
    next_reg: u8,
    /// Free-list of expression temporaries (reused within a message).
    temps: Vec<u8>,
}

impl<'a> Ctx<'a> {
    fn err(&self, detail: impl Into<String>) -> ProtocolError {
        ProtocolError::compile(&self.schema.id, detail)
    }

    fn alloc(&mut self, name: &str) -> Result<u8, ProtocolError> {
        if let Some(&slot) = self.regs.get(name) {
            return Ok(slot);
        }
        if !name.starts_with('_') && is_reserved(name) {
            return Err(self.err(format!(
                "register name {name:?} is reserved (operators and I/O atoms)"
            )));
        }
        let slot = self.next_reg;
        if slot as usize >= MAX_REGS {
            return Err(self.err(format!("register limit ({MAX_REGS}) exceeded at {name:?}")));
        }
        self.regs.insert(name.to_string(), slot);
        self.next_reg += 1;
        Ok(slot)
    }

    fn reg(&self, name: &str) -> Result<u8, ProtocolError> {
        self.regs
            .get(name)
            .copied()
            .ok_or_else(|| self.err(format!("unknown register {name:?}")))
    }

    fn alloc_temp(&mut self) -> Result<u8, ProtocolError> {
        if let Some(slot) = self.temps.pop() {
            return Ok(slot);
        }
        let slot = self.next_reg;
        if slot as usize >= MAX_REGS {
            return Err(self.err(format!(
                "register limit ({MAX_REGS}) exceeded (expression temporaries)"
            )));
        }
        self.next_reg += 1;
        Ok(slot)
    }

    fn release_temp(&mut self, slot: u8) {
        self.temps.push(slot);
    }
}

fn primitive(ty: &str) -> Option<(u8, bool, bool)> {
    Some(match ty {
        "i8" => (1, true, false),
        "i16" => (2, true, false),
        "i32" => (4, true, false),
        "i64" => (8, true, false),
        "u8" => (1, false, false),
        "u16" => (2, false, false),
        "u32" => (4, false, false),
        "u64" => (8, false, false),
        "f32" => (4, false, true),
        "f64" => (8, false, true),
        "bool" => (1, false, false),
        _ => return None,
    })
}

/// Compiles one schema into a [`CompiledProtocol`].
pub fn compile_schema(
    schema: ProtocolSchema,
    opts: &CompileOptions,
) -> Result<CompiledProtocol, ProtocolError> {
    let mut ctx = Ctx {
        schema: &schema,
        opts,
        regs: BTreeMap::new(),
        next_reg: 0,
        temps: Vec::new(),
    };

    let run_steps = match &schema.on_message {
        Some(on) => crate::steps::parse_run(&schema.id, &on.run)?,
        None => Vec::new(),
    };
    let mut preamble = Vec::new();
    let mut assigned_in_preamble = Vec::new();
    let mut framing = None;
    for step in &run_steps {
        compile_run_atom(
            &mut ctx,
            &mut preamble,
            step,
            &mut assigned_in_preamble,
            &mut framing,
        )?;
    }
    if preamble.is_empty() {
        return Err(ctx.err(
            "on_message.run must produce at least one framing step (check_len!/parse_header!)",
        ));
    }

    // Dispatch analysis: every `when` key must be a preamble register.
    for (name, msg) in &schema.messages {
        for key in msg.when.keys() {
            if !assigned_in_preamble.iter().any(|a| a == key) {
                return Err(ctx.err(format!(
                    "message {name:?}: when key {key:?} is not produced by on_message.run"
                )));
            }
        }
    }
    detect_when_overlap(&schema, &ctx)?;

    let single_key = schema
        .messages
        .values()
        .map(|m| m.when.keys().next().cloned())
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| ctx.err("message with empty when"))?;
    let uniform = single_key.iter().all(|k| Some(k) == single_key.first());

    let mut messages = Vec::new();
    let mut dispatch_table: HashMap<i64, u16> = HashMap::new();
    let mut linear: Vec<(Vec<WhenCond>, u16)> = Vec::new();
    let preamble_regs = ctx.regs.clone();
    let preamble_next = ctx.next_reg;
    for (idx, (name, msg)) in schema.messages.iter().enumerate() {
        let idx16 = u16::try_from(idx).map_err(|_| ctx.err("too many messages"))?;
        // Registers are frame-local: the preamble runs, then exactly one
        // message program. Each message gets a fresh register space, with
        // the preamble slots restored afterwards for `when` resolution.
        ctx.regs = preamble_regs.clone();
        ctx.next_reg = preamble_next;
        ctx.temps.clear();
        let program = compile_message(&mut ctx, name, msg)?;
        ctx.regs = preamble_regs.clone();
        ctx.next_reg = preamble_next;
        ctx.temps.clear();
        messages.push(MessageProgram {
            name: Arc::from(name.as_str()),
            name_hash: name_hash(name),
            policy: Arc::from(msg.policy.as_deref().unwrap_or("default")),
            after: msg.after.iter().map(|a| name_hash(a)).collect(),
            keepalive: msg.keepalive.clone(),
            program,
        });
        if uniform {
            let key = single_key[0].clone();
            let _ = ctx.reg(&key)?;
            let values = when_set(msg.when.get(&key).unwrap());
            if let WhenSet::Int(xs) = &values {
                for v in xs {
                    if dispatch_table.insert(*v, idx16).is_some() {
                        return Err(ctx.err(format!("duplicate when value {v} for key {key:?}")));
                    }
                }
            }
        }
        let mut conds = Vec::new();
        for (key, val) in &msg.when {
            conds.push(WhenCond {
                reg: ctx.reg(key)?,
                values: when_set(val),
            });
        }
        linear.push((conds, idx16));
    }

    let dispatch = if uniform {
        let key = single_key[0].clone();
        let reg = ctx.reg(&key)?;
        if dispatch_table.is_empty() {
            Dispatch::Linear(linear)
        } else {
            let _ = key;
            Dispatch::Int {
                reg,
                table: dispatch_table,
            }
        }
    } else {
        Dispatch::Linear(linear)
    };
    let dispatch_reg = schema
        .messages
        .values()
        .next()
        .and_then(|m| m.when.keys().next().cloned())
        .and_then(|k| ctx.regs.get(&k).copied());

    let mut policies: HashMap<String, PolicySpec> = schema
        .policies
        .iter()
        .map(|(k, p)| {
            (
                k.clone(),
                PolicySpec {
                    weight: p.weight,
                    on_repeat: p.on_repeat.clone(),
                },
            )
        })
        .collect();
    if !policies.contains_key("unknown_header") {
        // Framing/unknown-header violations fall back to `default`.
        let _ = &mut policies;
    }
    let unknown_policy = Arc::from(if policies.contains_key("unknown_header") {
        "unknown_header"
    } else {
        "default"
    });

    Ok(CompiledProtocol {
        schema_id: Arc::from(schema.id.as_str()),
        mode: schema.mode,
        ports: schema.transport.ports.clone(),
        framing,
        preamble,
        messages,
        dispatch,
        policies,
        unknown_policy,
        dispatch_reg,
    })
}

fn when_set(v: &WhenValue) -> WhenSet {
    let mut ints = Vec::new();
    let mut strs = Vec::new();
    let mut push = |v: &serde_yaml::Value| match v {
        serde_yaml::Value::Number(n) => {
            ints.push(n.as_i64().unwrap_or(0));
        }
        serde_yaml::Value::Bool(b) => ints.push(*b as i64),
        other => strs.push(yaml_str(other)),
    };
    match v {
        WhenValue::One(x) => push(x),
        WhenValue::Many(xs) => xs.iter().for_each(&mut push),
    }
    if !ints.is_empty() {
        WhenSet::Int(ints)
    } else {
        WhenSet::Str(strs)
    }
}

fn yaml_str(v: &serde_yaml::Value) -> String {
    match v {
        serde_yaml::Value::String(s) => s.clone(),
        serde_yaml::Value::Number(n) => n.to_string(),
        serde_yaml::Value::Bool(b) => b.to_string(),
        _ => String::new(),
    }
}

fn detect_when_overlap(schema: &ProtocolSchema, ctx: &Ctx<'_>) -> Result<(), ProtocolError> {
    let names: Vec<&String> = schema.messages.keys().collect();
    for i in 0..names.len() {
        for j in i + 1..names.len() {
            let a = &schema.messages[names[i]];
            let b = &schema.messages[names[j]];
            for (key, va) in &a.when {
                if let Some(vb) = b.when.get(key) {
                    if overlap(va, vb) {
                        let a_name = names[i];
                        let b_name = names[j];
                        return Err(ctx.err(format!(
                            "when overlap on {key:?} between messages {a_name:?} and {b_name:?}"
                        )));
                    }
                }
            }
        }
    }
    Ok(())
}

fn overlap(a: &WhenValue, b: &WhenValue) -> bool {
    let set_a = when_set(a);
    let set_b = when_set(b);
    match (&set_a, &set_b) {
        (WhenSet::Int(xs), WhenSet::Int(ys)) => xs.iter().any(|x| ys.contains(x)),
        (WhenSet::Str(xs), WhenSet::Str(ys)) => xs.iter().any(|x| ys.contains(x)),
        _ => false,
    }
}

fn compile_run_atom(
    ctx: &mut Ctx<'_>,
    out: &mut Vec<Instr>,
    step: &RunStep,
    assigned: &mut Vec<String>,
    framing: &mut Option<FrameSpec>,
) -> Result<(), ProtocolError> {
    match step.name.as_str() {
        "check_len" => {
            let offset = arg_int(&step.args, "offset").unwrap_or(0);
            let prefix_size = arg_int(&step.args, "size").unwrap_or(4);
            let endian = parse_endian(&step.args).unwrap_or(Endian::Big);
            let counts = match arg_str(&step.args, "counts").as_deref() {
                Some("data") => LenCounts::Data,
                _ => LenCounts::HeaderPlusData,
            };
            let header_size = arg_int(&step.args, "header_size").unwrap_or(2) as u64;
            let max = arg_int(&step.args, "max").unwrap_or(65_536) as u64;
            *framing = Some(FrameSpec {
                offset: offset as u8,
                prefix_size: prefix_size as u8,
                endian,
                counts,
                header_size,
                max,
            });
            let len_reg = ctx.alloc("frame_len")?;
            out.push(Instr::ReadFixed {
                dst: len_reg,
                size: prefix_size as u8,
                endian,
                signed: false,
            });
            out.push(Instr::CheckFrameLen {
                len_reg,
                offset: offset as u8,
                prefix_size: prefix_size as u8,
                endian,
                counts,
                header_size,
                max,
            });
            assigned.push("frame_len".into());
            if let Some(as_name) = arg_str(&step.args, "as") {
                assigned.push(as_name.clone());
            }
        }
        "parse_header" => {
            let dst_name = arg_str(&step.args, "as").unwrap_or_else(|| "header".into());
            let size = arg_int(&step.args, "size").unwrap_or(2);
            let endian = parse_endian(&step.args).unwrap_or(Endian::Big);
            if !(1..=8).contains(&size) {
                return Err(ctx.err(format!("parse_header size {size} out of range 1..=8")));
            }
            let dst = ctx.alloc(&dst_name)?;
            out.push(Instr::ReadFixed {
                dst,
                size: size as u8,
                endian,
                signed: false,
            });
            assigned.push(dst_name);
        }
        other => {
            return Err(ctx.err(format!(
                "unknown run atom {other:?}; available: {}",
                crate::macros::run_atoms_list()
            )))
        }
    }
    Ok(())
}

fn parse_endian(args: &BTreeMap<String, serde_yaml::Value>) -> Option<Endian> {
    match arg_str(args, "endian").as_deref() {
        Some("little") => Some(Endian::Little),
        Some("big") => Some(Endian::Big),
        _ => None,
    }
}

fn compile_message(
    ctx: &mut Ctx<'_>,
    name: &str,
    msg: &MessageDef,
) -> Result<Vec<Instr>, ProtocolError> {
    let mut prog = Vec::new();
    for line in &msg.validate {
        let context = format!("message {name:?}, field {:?}", line.field);
        let field_reg = ctx.alloc(&line.field)?;
        expand_type(ctx, &line.line.type_name, field_reg, 0, &mut prog)
            .map_err(|e| with_context(e, &context))?;
        emit_field_ops(ctx, field_reg, &line.line.ops, &mut prog)
            .map_err(|e| with_context(e, &context))?;
    }
    prog.push(Instr::Halt);
    if prog.len() > MAX_INSTRS_PER_MESSAGE {
        return Err(ctx.err(format!(
            "message {name:?}: program exceeds {MAX_INSTRS_PER_MESSAGE} instructions"
        )));
    }
    Ok(prog)
}

fn with_context(e: ProtocolError, context: &str) -> ProtocolError {
    match e {
        ProtocolError::Compile { schema, detail } => ProtocolError::Compile {
            schema,
            detail: format!("{context}: {detail}"),
        },
        other => other,
    }
}

/// Expands a wire type into instructions writing the final value to `dst`.
fn expand_type(
    ctx: &mut Ctx<'_>,
    type_name: &str,
    dst: u8,
    depth: usize,
    out: &mut Vec<Instr>,
) -> Result<(), ProtocolError> {
    if depth > MAX_TYPE_DEPTH {
        return Err(ctx.err(format!("type nesting deeper than {MAX_TYPE_DEPTH}")));
    }
    if let Some((size, signed, is_float)) = primitive(type_name) {
        if is_float {
            out.push(Instr::ReadFloat {
                dst,
                size,
                endian: Endian::Big,
            });
        } else if type_name == "bool" {
            out.push(Instr::ReadFixed {
                dst,
                size,
                endian: Endian::Big,
                signed: false,
            });
            out.push(Instr::RangeOk {
                reg: dst,
                min: 0,
                max: 1,
            });
        } else {
            out.push(Instr::ReadFixed {
                dst,
                size,
                endian: Endian::Big,
                signed,
            });
        }
        return Ok(());
    }
    let def = ctx
        .schema
        .types
        .get(type_name)
        .ok_or_else(|| ctx.err(format!("unknown type {type_name:?}")))?;
    match def {
        TypeDef::Sugar(sugar) => expand_sugar(ctx, sugar, dst, out),
        TypeDef::Body { body } => compile_steps(ctx, body, Some(dst), depth + 1, out),
        TypeDef::Composite(fields) => {
            let mut last = dst;
            for f in fields {
                let sub = ctx.alloc("_tmp")?;
                expand_type(ctx, &f.type_name, sub, depth + 1, out)?;
                last = sub;
            }
            out.push(Instr::Copy { dst, src: last });
            Ok(())
        }
    }
}

fn expand_sugar(
    ctx: &mut Ctx<'_>,
    sugar: &SugarRead,
    dst: u8,
    out: &mut Vec<Instr>,
) -> Result<(), ProtocolError> {
    if let Some(n) = sugar.fixed {
        if !matches!(n, 1 | 2 | 4 | 8) {
            return Err(ctx.err(format!("fixed size {n} not in 1/2/4/8")));
        }
        let endian = sugar.endian.unwrap_or(Endian::Big);
        match sugar.mask_ok {
            Some(MaskOk { bits, value }) if n > 1 => {
                // Unrolled per-byte read with mask check.
                let acc = ctx.alloc("_acc")?;
                let b = ctx.alloc("_b")?;
                out.push(Instr::Const { dst: acc, value: 0 });
                for _ in 0..n {
                    out.push(Instr::ReadFixed {
                        dst: b,
                        size: 1,
                        endian: Endian::Big,
                        signed: false,
                    });
                    out.push(Instr::MaskOk {
                        reg: b,
                        bits,
                        value,
                    });
                    out.push(Instr::BinOp {
                        op: BinOp::Shl,
                        dst: acc,
                        a: Operand::Reg(acc),
                        b: Operand::Const(8),
                    });
                    out.push(Instr::BinOp {
                        op: BinOp::Or,
                        dst: acc,
                        a: Operand::Reg(acc),
                        b: Operand::Reg(b),
                    });
                }
                out.push(Instr::Copy { dst, src: acc });
            }
            _ => out.push(Instr::ReadFixed {
                dst,
                size: n as u8,
                endian,
                signed: false,
            }),
        }
        if sugar.decode.is_some() && !matches!(sugar.decode, Some(Decode::None)) {
            return Err(ctx.err("decode applies to byte reads (prefix/terminator) only"));
        }
        return Ok(());
    }
    if let Some(prefix_ty) = &sugar.prefix {
        let (size, signed, is_float) = primitive(prefix_ty)
            .ok_or_else(|| ctx.err(format!("bad prefix type {prefix_ty:?}")))?;
        if is_float {
            return Err(ctx.err(format!("prefix type {prefix_ty:?} must be an integer")));
        }
        let len_reg = ctx.alloc("_len")?;
        out.push(Instr::ReadFixed {
            dst: len_reg,
            size,
            endian: Endian::Big,
            signed,
        });
        let max_len = sugar.max_len.unwrap_or(65_536);
        out.push(Instr::LenOk {
            reg: len_reg,
            min: 0,
            max: max_len,
        });
        out.push(Instr::ReadBytes {
            dst,
            len_reg,
            max: max_len,
        });
        emit_decode(sugar.decode, dst, out)?;
        return Ok(());
    }
    if let Some(term) = sugar.terminator {
        let max_len = sugar.max_len.unwrap_or(4_096);
        out.push(Instr::ReadUntil {
            dst,
            term,
            max: max_len,
        });
        emit_decode(sugar.decode, dst, out)?;
        return Ok(());
    }
    Err(ctx.err("sugar type needs one of fixed/prefix/terminator"))
}

fn emit_decode(decode: Option<Decode>, dst: u8, out: &mut Vec<Instr>) -> Result<(), ProtocolError> {
    match decode {
        None | Some(Decode::None) => Ok(()),
        Some(enc) => {
            out.push(Instr::Decode { dst, src: dst, enc });
            Ok(())
        }
    }
}

fn emit_field_ops(
    ctx: &mut Ctx<'_>,
    reg: u8,
    ops: &[FieldOp],
    out: &mut Vec<Instr>,
) -> Result<(), ProtocolError> {
    for op in ops {
        match op {
            FieldOp::Gt(n) => out.push(Instr::Gt { reg, n: *n }),
            FieldOp::Lt(n) => out.push(Instr::Lt { reg, n: *n }),
            FieldOp::LenGt(n) => out.push(Instr::LenGt { reg, n: *n }),
            FieldOp::LenLt(n) => out.push(Instr::LenLt { reg, n: *n }),
            FieldOp::Regex(pattern) => {
                let re = regex::Regex::new(pattern)
                    .map_err(|e| ctx.err(format!("invalid regex {pattern:?}: {e}")))?;
                out.push(Instr::RegexOk {
                    reg,
                    re: Arc::new(re),
                });
            }
            FieldOp::Charset(class) => out.push(Instr::CharsetOk { reg, class: *class }),
            FieldOp::In(vals) => out.push(Instr::InSet {
                reg,
                set: vals.clone().into(),
            }),
            FieldOp::NotIn(name) => {
                let set =
                    ctx.opts
                        .datasets
                        .get(name)
                        .ok_or_else(|| ProtocolError::MissingDataset {
                            name: name.clone(),
                            schema: ctx.schema.id.clone(),
                        })?;
                out.push(Instr::NotInSet {
                    reg,
                    set: Arc::clone(set),
                });
            }
            FieldOp::Required => {}
        }
    }
    Ok(())
}

fn compile_steps(
    ctx: &mut Ctx<'_>,
    steps: &[Step],
    return_dst: Option<u8>,
    depth: usize,
    out: &mut Vec<Instr>,
) -> Result<(), ProtocolError> {
    if depth > MAX_TYPE_DEPTH {
        return Err(ctx.err(format!("macro body nesting deeper than {MAX_TYPE_DEPTH}")));
    }
    for step in steps {
        match step {
            Step::Assign { name, expr } => {
                compile_assign(ctx, name, expr, out)?;
            }
            Step::While { bound, body } => {
                compile_while(ctx, bound, body, depth, out)?;
            }
            Step::If { cond, body } => {
                compile_if(ctx, cond, body, return_dst, depth, out)?;
            }
            Step::Statement(text) => {
                compile_statement(ctx, text, return_dst, out)?;
            }
        }
    }
    Ok(())
}

/// Result of compiling a subexpression: a constant, or a register plus
/// whether it is a compiler temporary that must be released after use.
enum Res {
    Const(i64),
    Reg(u8, bool),
}

impl Res {
    fn operand(&self) -> Operand {
        match self {
            Self::Const(n) => Operand::Const(*n),
            Self::Reg(r, _) => Operand::Reg(*r),
        }
    }
}

fn free_res(ctx: &mut Ctx<'_>, r: Res) {
    if let Res::Reg(slot, true) = r {
        ctx.release_temp(slot);
    }
}

/// Materializes a result into a register (constants get a temp slot).
fn into_reg(ctx: &mut Ctx<'_>, r: Res, out: &mut Vec<Instr>) -> Result<(u8, bool), ProtocolError> {
    Ok(match r {
        Res::Reg(reg, temp) => (reg, temp),
        Res::Const(n) => {
            let t = ctx.alloc_temp()?;
            out.push(Instr::Const { dst: t, value: n });
            (t, true)
        }
    })
}

/// Compiles `expr` writing the final value into `dst` (which may be read
/// by the expression itself — the write lands last).
fn compile_expr_into(
    ctx: &mut Ctx<'_>,
    expr: &Expr,
    dst: u8,
    out: &mut Vec<Instr>,
) -> Result<(), ProtocolError> {
    match compile_sub(ctx, expr, out)? {
        Res::Const(n) => out.push(Instr::Const { dst, value: n }),
        Res::Reg(r, temp) => {
            if r != dst {
                out.push(Instr::Copy { dst, src: r });
            }
            if temp {
                ctx.release_temp(r);
            }
        }
    }
    Ok(())
}

fn compile_sub(ctx: &mut Ctx<'_>, expr: &Expr, out: &mut Vec<Instr>) -> Result<Res, ProtocolError> {
    match expr {
        Expr::Int(n) => Ok(Res::Const(*n)),
        Expr::Reg(name) => Ok(Res::Reg(ctx.reg(name)?, false)),
        Expr::Bin(op, a, b) => {
            let ra = compile_sub(ctx, a, out)?;
            let rb = compile_sub(ctx, b, out)?;
            let t = ctx.alloc_temp()?;
            out.push(Instr::BinOp {
                op: *op,
                dst: t,
                a: ra.operand(),
                b: rb.operand(),
            });
            free_res(ctx, rb);
            free_res(ctx, ra);
            Ok(Res::Reg(t, true))
        }
        Expr::Neg(a) => {
            let ra = compile_sub(ctx, a, out)?;
            let (src, temp) = into_reg(ctx, ra, out)?;
            let t = ctx.alloc_temp()?;
            out.push(Instr::Neg { dst: t, src });
            if temp {
                ctx.release_temp(src);
            }
            Ok(Res::Reg(t, true))
        }
        Expr::Not(a) => {
            let ra = compile_sub(ctx, a, out)?;
            let (src, temp) = into_reg(ctx, ra, out)?;
            let t = ctx.alloc_temp()?;
            out.push(Instr::Not { dst: t, src });
            if temp {
                ctx.release_temp(src);
            }
            Ok(Res::Reg(t, true))
        }
        Expr::Min(..) => Err(ctx.err("min! is only valid in a while bound")),
    }
}

fn compile_while(
    ctx: &mut Ctx<'_>,
    bound: &str,
    body: &[Step],
    depth: usize,
    out: &mut Vec<Instr>,
) -> Result<(), ProtocolError> {
    let expr = crate::expr::parse_expression(&ctx.schema.id, bound)?;
    let (bound_op, cap, temp) = match &expr {
        Expr::Int(n) => {
            if *n < 0 {
                return Err(ctx.err("while bound must be non-negative"));
            }
            (Operand::Const(*n), None, None)
        }
        Expr::Min(a, b) => {
            let (cap, var) = match (a.as_ref(), b.as_ref()) {
                (_, Expr::Int(n)) => (*n, a.as_ref()),
                (Expr::Int(n), _) => (*n, b.as_ref()),
                _ => return Err(ctx.err("while min! needs a constant cap: while min!(expr, cap):")),
            };
            if cap < 0 {
                return Err(ctx.err("while cap must be non-negative"));
            }
            match var {
                Expr::Int(m) => (Operand::Const((*m).min(cap)), None, None),
                e => {
                    let r = compile_sub(ctx, e, out)?;
                    match r {
                        Res::Const(c) => (Operand::Const(c.min(cap)), None, None),
                        Res::Reg(reg, is_temp) => {
                            (Operand::Reg(reg), Some(cap as u64), is_temp.then_some(reg))
                        }
                    }
                }
            }
        }
        _ => {
            return Err(ctx.err("unbounded while: the bound must be a constant or min!(expr, cap)"))
        }
    };
    let mut body_instrs = Vec::new();
    compile_steps(ctx, body, None, depth + 1, &mut body_instrs)?;
    out.push(Instr::Loop {
        bound: bound_op,
        cap,
        body: body_instrs.into(),
    });
    if let Some(t) = temp {
        ctx.release_temp(t);
    }
    Ok(())
}

fn compile_if(
    ctx: &mut Ctx<'_>,
    cond: &str,
    body: &[Step],
    return_dst: Option<u8>,
    depth: usize,
    out: &mut Vec<Instr>,
) -> Result<(), ProtocolError> {
    let expr = crate::expr::parse_expression(&ctx.schema.id, cond)?;
    match compile_sub(ctx, &expr, out)? {
        Res::Const(n) => {
            if n != 0 {
                compile_steps(ctx, body, return_dst, depth + 1, out)?;
            }
            Ok(())
        }
        Res::Reg(reg, temp) => {
            let at = out.len();
            out.push(Instr::BranchIfZero {
                cond: Operand::Reg(reg),
                skip: 0,
            });
            compile_steps(ctx, body, return_dst, depth + 1, out)?;
            let skip = out.len() - at - 1;
            let skip =
                u16::try_from(skip).map_err(|_| ctx.err("if block exceeds 65535 instructions"))?;
            out[at] = Instr::BranchIfZero {
                cond: Operand::Reg(reg),
                skip,
            };
            if temp {
                ctx.release_temp(reg);
            }
            Ok(())
        }
    }
}

fn compile_statement(
    ctx: &mut Ctx<'_>,
    text: &str,
    return_dst: Option<u8>,
    out: &mut Vec<Instr>,
) -> Result<(), ProtocolError> {
    match crate::steps::parse_statement(&ctx.schema.id, text)? {
        ParsedStatement::Return(reg) => {
            let src = ctx.reg(&reg)?;
            match return_dst {
                Some(dst) => out.push(Instr::Copy { dst, src }),
                None => return Err(ctx.err("return outside of a type expansion")),
            }
            Ok(())
        }
        ParsedStatement::Call { name, args } => compile_check(ctx, &name, &args, out),
    }
}

fn compile_check(
    ctx: &mut Ctx<'_>,
    name: &str,
    args: &[String],
    out: &mut Vec<Instr>,
) -> Result<(), ProtocolError> {
    let int = |i: usize| -> Result<i64, ProtocolError> {
        args.get(i)
            .and_then(|a| parse_int_literal(a))
            .ok_or_else(|| ctx.err(format!("{name}! argument {i} must be an integer")))
    };
    let arity = |want: &str| {
        ctx.err(format!(
            "{name}! expects {want} (statement macros: check_mask!(reg, bits, value), \
             check_range!(reg, min, max), check_len!(reg, min, max))"
        ))
    };
    match name {
        "check_mask" => {
            if args.len() != 3 {
                return Err(arity("3 args (reg, bits, value)"));
            }
            out.push(Instr::MaskOk {
                reg: ctx.reg(&args[0])?,
                bits: int(1)? as u8,
                value: int(2)? as u8,
            });
        }
        "check_range" => {
            if args.len() != 3 {
                return Err(arity("3 args (reg, min, max)"));
            }
            out.push(Instr::RangeOk {
                reg: ctx.reg(&args[0])?,
                min: int(1)?,
                max: int(2)?,
            });
        }
        "check_len" => {
            if args.len() != 3 {
                return Err(arity("3 args (reg, min, max)"));
            }
            let min = int(1)?;
            let max = int(2)?;
            if min < 0 || max < 0 || min > max {
                return Err(ctx.err(format!(
                    "check_len! bounds out of order or negative: [{min}, {max}]"
                )));
            }
            out.push(Instr::LenOk {
                reg: ctx.reg(&args[0])?,
                min: min as u64,
                max: max as u64,
            });
        }
        other => {
            return Err(ctx.err(format!(
                "unknown statement macro {other:?} (available: check_mask!, check_range!, \
                 check_len!, return)"
            )));
        }
    }
    Ok(())
}

fn need_arg<'a>(
    toks: &'a [(String, bool)],
    i: usize,
    opcode: &str,
    ctx: &Ctx<'_>,
) -> Result<&'a str, ProtocolError> {
    toks.get(i)
        .map(|(t, _)| t.as_str())
        .ok_or_else(|| ctx.err(format!("op {opcode:?} missing argument {i}")))
}

/// Compiles one assignment step: either an I/O atom call (`read`,
/// `decode`, `peek`) or an infix expression ([`crate::expr`]).
fn compile_assign(
    ctx: &mut Ctx<'_>,
    dst_name: &str,
    expr_text: &str,
    out: &mut Vec<Instr>,
) -> Result<(), ProtocolError> {
    let dst = ctx.alloc(dst_name)?;
    let first = tokenize(expr_text).into_iter().next().map(|(t, _)| t);
    match first.as_deref() {
        Some("read") => compile_read(ctx, dst, expr_text, out),
        Some("decode") => compile_decode(ctx, dst, expr_text, out),
        Some("peek") => compile_peek(ctx, dst, expr_text, out),
        _ => {
            let expr = crate::expr::parse_expression(&ctx.schema.id, expr_text)?;
            compile_expr_into(ctx, &expr, dst, out)
        }
    }
}

fn compile_read(
    ctx: &mut Ctx<'_>,
    dst: u8,
    op_text: &str,
    out: &mut Vec<Instr>,
) -> Result<(), ProtocolError> {
    let toks = tokenize(op_text);
    let opcode = "read";
    let ty = need_arg(&toks, 1, opcode, ctx)?;
    if ty == "bytes" {
        let src = need_arg(&toks, 2, opcode, ctx)?;
        let len_reg = ctx.reg(src)?;
        out.push(Instr::ReadBytes {
            dst,
            len_reg,
            max: u64::try_from(i64::MAX).unwrap_or(u64::MAX),
        });
        return Ok(());
    }
    if ty == "until" {
        let term = parse_int_literal(need_arg(&toks, 2, opcode, ctx)?)
            .ok_or_else(|| ctx.err("bad terminator"))?;
        let max = toks
            .get(4)
            .and_then(|(t, _)| parse_int_literal(t))
            .unwrap_or(4_096) as u64;
        out.push(Instr::ReadUntil {
            dst,
            term: term as u8,
            max,
        });
        return Ok(());
    }
    let mut endian = Endian::Big;
    for (t, _) in toks.iter().skip(2) {
        if t == "le" {
            endian = Endian::Little;
        }
    }
    let (size, signed, is_float) =
        primitive(ty).ok_or_else(|| ctx.err(format!("unknown primitive {ty:?}")))?;
    if is_float {
        out.push(Instr::ReadFloat { dst, size, endian });
    } else {
        out.push(Instr::ReadFixed {
            dst,
            size,
            endian,
            signed,
        });
    }
    Ok(())
}

fn compile_decode(
    ctx: &mut Ctx<'_>,
    dst: u8,
    op_text: &str,
    out: &mut Vec<Instr>,
) -> Result<(), ProtocolError> {
    let toks = tokenize(op_text);
    let opcode = "decode";
    let src = ctx.reg(need_arg(&toks, 1, opcode, ctx)?)?;
    let enc = match need_arg(&toks, 2, opcode, ctx)? {
        "utf8" => Decode::Utf8,
        "latin1" => Decode::Latin1,
        "b64" => Decode::B64,
        "b64url" => Decode::B64Url,
        "hex" => Decode::Hex,
        "none" => Decode::None,
        other => return Err(ctx.err(format!("unknown decode {other:?}"))),
    };
    out.push(Instr::Decode { dst, src, enc });
    Ok(())
}

fn compile_peek(
    ctx: &mut Ctx<'_>,
    dst: u8,
    op_text: &str,
    out: &mut Vec<Instr>,
) -> Result<(), ProtocolError> {
    let toks = tokenize(op_text);
    let size = parse_int_literal(need_arg(&toks, 1, "peek", ctx)?)
        .ok_or_else(|| ctx.err("bad peek size"))?;
    out.push(Instr::Peek {
        dst,
        size: size as u8,
    });
    Ok(())
}

/// Value used by the VM to carry a failure reason out of the hot loop.
pub type VmFail = String;

/// Terminator scan: SIMD-accelerated via memchr when the `simd` feature
/// is on, scalar byte loop otherwise.
fn find_terminator(haystack: &[u8], term: u8) -> Option<usize> {
    #[cfg(feature = "simd")]
    {
        memchr::memchr(term, haystack)
    }
    #[cfg(not(feature = "simd"))]
    {
        haystack.iter().position(|&b| b == term)
    }
}

/// UTF-8 validation: SIMD-accelerated via simdutf8 when the `simd`
/// feature is on; std otherwise (same accept/reject semantics).
fn validate_utf8(bytes: &[u8]) -> Result<&str, &'static str> {
    #[cfg(feature = "simd")]
    {
        simdutf8::basic::from_utf8(bytes).map_err(|_| "invalid utf-8")
    }
    #[cfg(not(feature = "simd"))]
    {
        std::str::from_utf8(bytes).map_err(|_| "invalid utf-8")
    }
}

/// Executes a program. Fails with a human-readable reason on the first
/// violated instruction; registers/cursor are left unspecified on failure.
pub fn run_vm(
    program: &[Instr],
    cur: &mut std::io::Cursor<&[u8]>,
    regs: &mut [Value; MAX_REGS],
) -> Result<(), VmFail> {
    run_block(program, cur, regs)
}

fn reg_or_const(op: Operand, regs: &[Value; MAX_REGS]) -> i64 {
    match op {
        Operand::Reg(r) => regs[r as usize].as_num().unwrap_or(0),
        Operand::Const(n) => n,
    }
}

fn bin_apply(op: BinOp, a: i64, b: i64) -> i64 {
    match op {
        BinOp::And => a & b,
        BinOp::Or => a | b,
        BinOp::Xor => a ^ b,
        BinOp::Shl => a.checked_shl(b.clamp(0, 63) as u32).unwrap_or(0),
        BinOp::Shr => a.checked_shr(b.clamp(0, 63) as u32).unwrap_or(0),
        BinOp::Add => a.saturating_add(b),
        BinOp::Sub => a.saturating_sub(b),
        BinOp::Mul => a.saturating_mul(b),
    }
}

fn read_fixed(
    cur: &mut std::io::Cursor<&[u8]>,
    size: u8,
    endian: Endian,
    signed: bool,
) -> Option<i64> {
    let mut buf = [0u8; 8];
    let slice = cur
        .get_ref()
        .get(cur.position() as usize..)?
        .get(..size as usize)?;
    cur.set_position(cur.position() + size as u64);
    match endian {
        Endian::Big => buf[..size as usize].copy_from_slice(slice),
        Endian::Little => {
            buf[..size as usize].copy_from_slice(slice);
            buf[..size as usize].reverse();
        }
    }
    let raw = u64::from_be_bytes(buf);
    let unsigned = raw >> ((8 - size as u32) * 8);
    Some(if signed {
        match size {
            1 => unsigned as u8 as i8 as i64,
            2 => unsigned as u16 as i16 as i64,
            4 => unsigned as u32 as i32 as i64,
            _ => unsigned as usize as i64,
        }
    } else {
        unsigned as i64
    })
}

fn run_block(
    program: &[Instr],
    cur: &mut std::io::Cursor<&[u8]>,
    regs: &mut [Value; MAX_REGS],
) -> Result<(), VmFail> {
    let mut i = 0;
    while i < program.len() {
        let instr = &program[i];
        i += 1;
        match instr {
            Instr::Const { dst, value } => regs[*dst as usize] = Value::Int(*value),
            Instr::Copy { dst, src } => regs[*dst as usize] = regs[*src as usize].clone(),
            Instr::ReadFixed {
                dst,
                size,
                endian,
                signed,
            } => {
                let n = read_fixed(cur, *size, *endian, *signed)
                    .ok_or_else(|| "unexpected end of frame".to_string())?;
                regs[*dst as usize] = Value::Int(n);
            }
            Instr::ReadFloat { dst, size, endian } => {
                let bits = read_fixed(cur, *size, *endian, false)
                    .ok_or_else(|| "unexpected end of frame".to_string())?;
                let f = match size {
                    4 => f32::from_bits(bits as u32) as f64,
                    _ => f64::from_bits(bits as u64),
                };
                regs[*dst as usize] = Value::Float(f);
            }
            Instr::ReadBytes { dst, len_reg, max } => {
                let len = regs[*len_reg as usize].as_num().unwrap_or(0);
                if len < 0 || len as u64 > *max {
                    return Err(format!("declared byte length {len} out of range"));
                }
                let pos = cur.position() as usize;
                let slice = cur
                    .get_ref()
                    .get(pos..)
                    .and_then(|rest| rest.get(..len as usize))
                    .ok_or_else(|| "unexpected end of frame".to_string())?;
                cur.set_position(pos as u64 + len as u64);
                regs[*dst as usize] = Value::Bytes(slice.to_vec());
            }
            Instr::ReadUntil { dst, term, max } => {
                let pos = cur.position() as usize;
                let rest = cur
                    .get_ref()
                    .get(pos..)
                    .ok_or_else(|| "unexpected end of frame".to_string())?;
                let idx =
                    find_terminator(rest, *term).ok_or_else(|| "missing terminator".to_string())?;
                if idx as u64 > *max {
                    return Err(format!("run exceeds max {max}"));
                }
                regs[*dst as usize] = Value::Bytes(rest[..idx].to_vec());
                cur.set_position(pos as u64 + idx as u64 + 1);
            }
            Instr::Peek { dst, size } => {
                let pos = cur.position() as usize;
                let slice = cur
                    .get_ref()
                    .get(pos..)
                    .and_then(|rest| rest.get(..*size as usize))
                    .ok_or_else(|| "unexpected end of frame".to_string())?;
                regs[*dst as usize] = Value::Bytes(slice.to_vec());
            }
            Instr::Decode { dst, src, enc } => {
                let raw = match &regs[*src as usize] {
                    Value::Bytes(b) => b.clone(),
                    Value::Str(s) => s.clone().into_bytes(),
                    other => {
                        return Err(format!("decode on {other:?}"));
                    }
                };
                let decoded = match enc {
                    Decode::None => String::from_utf8_lossy(&raw).into_owned(),
                    Decode::Utf8 => validate_utf8(&raw)?.to_owned(),
                    Decode::Latin1 => raw.iter().map(|&b| b as char).collect(),
                    Decode::B64 | Decode::B64Url => {
                        let decoded = b64_decode(&raw, matches!(enc, Decode::B64))
                            .ok_or_else(|| "invalid base64".to_string())?;
                        String::from_utf8(decoded)
                            .map_err(|_| "invalid utf-8 after base64".to_string())?
                    }
                    Decode::Hex => {
                        let decoded = hex_decode(&raw).ok_or_else(|| "invalid hex".to_string())?;
                        String::from_utf8(decoded)
                            .map_err(|_| "invalid utf-8 after hex".to_string())?
                    }
                };
                regs[*dst as usize] = Value::Str(decoded);
            }
            Instr::BinOp { op, dst, a, b } => {
                let va = reg_or_const(*a, regs);
                let vb = reg_or_const(*b, regs);
                regs[*dst as usize] = Value::Int(bin_apply(*op, va, vb));
            }
            Instr::Neg { dst, src } => {
                let v = regs[*src as usize].as_num().unwrap_or(0);
                regs[*dst as usize] = Value::Int(-v);
            }
            Instr::Not { dst, src } => {
                let v = regs[*src as usize].as_num().unwrap_or(0);
                regs[*dst as usize] = Value::Int(if v == 0 { 1 } else { 0 });
            }
            Instr::BranchIfZero { cond, skip } => {
                if reg_or_const(*cond, regs) == 0 {
                    i += *skip as usize;
                }
            }
            Instr::Loop { bound, cap, body } => {
                let mut times = reg_or_const(*bound, regs).max(0);
                if let Some(c) = cap {
                    times = times.min(*c as i64);
                }
                for _ in 0..times {
                    run_block(body, cur, regs)?;
                }
            }
            Instr::MaskOk { reg, bits, value } => {
                let v = regs[*reg as usize].as_num().unwrap_or(0);
                if v & *bits as i64 != *value as i64 {
                    return Err(format!(
                        "mask check failed: {v:#04x} & {bits:#04x} != {value:#04x}"
                    ));
                }
            }
            Instr::RangeOk { reg, min, max } => {
                let v = regs[*reg as usize].as_num().unwrap_or(0);
                if v < *min || v > *max {
                    return Err(format!("value {v} out of range [{min}, {max}]"));
                }
            }
            Instr::LenOk { reg, min, max } => {
                let v = &regs[*reg as usize];
                let len = match v {
                    Value::Bytes(b) => b.len() as u64,
                    Value::Str(s) => s.len() as u64,
                    Value::Int(n) if *n >= 0 => *n as u64,
                    other => return Err(format!("len check on {other:?}")),
                };
                if len < *min || len > *max {
                    return Err(format!("length {len} out of range [{min}, {max}]"));
                }
            }
            Instr::CheckFrameLen {
                len_reg,
                offset,
                prefix_size,
                counts,
                header_size,
                max,
                ..
            } => {
                let declared = regs[*len_reg as usize].as_num().unwrap_or(0);
                if declared < 0 || declared as u64 > *max {
                    return Err(format!("declared length {declared} exceeds max {max}"));
                }
                let frame_len = cur.get_ref().len() as i64;
                let consumed = *offset as i64 + *prefix_size as i64;
                let expected = match counts {
                    LenCounts::HeaderPlusData => declared,
                    LenCounts::Data => declared + *header_size as i64,
                };
                if frame_len - consumed != expected {
                    return Err(format!(
                        "framing mismatch: frame holds {} data bytes, length field says {expected}",
                        frame_len - consumed
                    ));
                }
            }
            Instr::Gt { reg, n } => {
                let v = regs[*reg as usize].as_num().unwrap_or(0);
                if v <= *n {
                    return Err(format!("bound failed: {v} > {n}"));
                }
            }
            Instr::Lt { reg, n } => {
                let v = regs[*reg as usize].as_num().unwrap_or(0);
                if v >= *n {
                    return Err(format!("bound failed: {v} < {n}"));
                }
            }
            Instr::LenGt { reg, n } => {
                let v = &regs[*reg as usize];
                let len = value_len(v)?;
                if len <= *n {
                    return Err(format!("length bound failed: {len} > {n}"));
                }
            }
            Instr::LenLt { reg, n } => {
                let v = &regs[*reg as usize];
                let len = value_len(v)?;
                if len >= *n {
                    return Err(format!("length bound failed: {len} < {n}"));
                }
            }
            Instr::CharsetOk { reg, class } => {
                let v = &regs[*reg as usize];
                let bytes = v
                    .as_bytes()
                    .ok_or_else(|| "charset check on numeric".to_string())?;
                if !class.matches(bytes) {
                    return Err("charset check failed".to_string());
                }
            }
            Instr::RegexOk { reg, re } => {
                let v = &regs[*reg as usize];
                let s = match v {
                    Value::Str(s) => s.clone(),
                    Value::Bytes(b) => String::from_utf8_lossy(b).into_owned(),
                    Value::Int(n) => n.to_string(),
                    Value::Float(f) => f.to_string(),
                };
                if !re.is_match(&s) {
                    return Err(format!("regex {:?} did not match", re.as_str()));
                }
            }
            Instr::InSet { reg, set } => {
                let v = &regs[*reg as usize];
                let s = value_string(v);
                if !set.iter().any(|x| x == &s) {
                    return Err(format!("value {s:?} not in allowed set"));
                }
            }
            Instr::NotInSet { reg, set } => {
                let v = &regs[*reg as usize];
                let s = value_string(v);
                if set.iter().any(|x| x == &s) {
                    return Err(format!("value {s:?} is in denied dataset"));
                }
            }
            Instr::Halt => return Ok(()),
        }
    }
    Ok(())
}

fn value_len(v: &Value) -> Result<u64, VmFail> {
    match v {
        Value::Bytes(b) => Ok(b.len() as u64),
        Value::Str(s) => Ok(s.len() as u64),
        other => Err(format!("length op on {other:?}")),
    }
}

fn value_string(v: &Value) -> String {
    match v {
        Value::Str(s) => s.clone(),
        Value::Bytes(b) => String::from_utf8_lossy(b).into_owned(),
        Value::Int(n) => n.to_string(),
        Value::Float(f) => f.to_string(),
    }
}

const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64URL_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn b64_decode(input: &[u8], std_alpha: bool) -> Option<Vec<u8>> {
    let alpha: &[u8; 64] = if std_alpha {
        B64_ALPHABET
    } else {
        B64URL_ALPHABET
    };
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    for &b in input {
        if b == b'=' {
            break;
        }
        let idx = alpha.iter().position(|&a| a == b)? as u32;
        acc = (acc << 6) | idx;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

fn hex_decode(input: &[u8]) -> Option<Vec<u8>> {
    let hex = |b: u8| -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    };
    if input.len() % 2 != 0 {
        return None;
    }
    input
        .chunks(2)
        .map(|pair| Some(hex(pair[0])? << 4 | hex(pair[1])?))
        .collect()
}

/// Convenience: compiles and wraps a [`Violation`] factory bound to a
/// schema's policy lookup.
impl CompiledProtocol {
    /// Builds a violation for this protocol with the named policy.
    pub fn violation(&self, policy: &str, message: &str, reason: impl Into<String>) -> Violation {
        Violation {
            schema: Arc::clone(&self.schema_id),
            policy: Arc::from(policy),
            message: Arc::from(message),
            reason: reason.into(),
            escalated: false,
        }
    }

    /// The severity spec of a policy by name.
    pub fn policy(&self, name: &str) -> Option<&PolicySpec> {
        self.policies.get(name)
    }

    /// Dispatches on the register values produced by the preamble.
    pub fn dispatch(&self, regs: &[Value; MAX_REGS]) -> Option<u16> {
        match &self.dispatch {
            Dispatch::Int { reg, table, .. } => {
                let v = regs[*reg as usize].as_num()?;
                table.get(&v).copied()
            }
            Dispatch::Linear(entries) => entries
                .iter()
                .find(|(conds, _)| {
                    conds
                        .iter()
                        .all(|c| c.values.contains(&regs[c.reg as usize]))
                })
                .map(|(_, idx)| *idx),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compile_text(text: &str) -> Result<CompiledProtocol, ProtocolError> {
        let schema = ProtocolSchema::from_yaml(text)?;
        compile_schema(schema, &CompileOptions::default())
    }

    /// Schema whose message validates one field of type `T` (so the type is
    /// actually compiled into the program).
    fn schema_with(validate: &str, types: &str) -> String {
        format!(
            r#"
id: t
transport: {{protocol: tcp, ports: [1]}}
on_message:
  run: check_len! | parse_header!
policies: {{default: {{weight: 1}}}}
types:
{types}
messages:
  m:
    when: {{header: 1}}
    validate:
{validate}
"#
        )
    }

    fn compiled_with_type(ty_body: &str) -> Result<CompiledProtocol, ProtocolError> {
        compile_text(&schema_with("      - v: T", ty_body))
    }

    #[test]
    fn rejects_unbounded_while() {
        let err = compiled_with_type(
            "  T:\n    body:\n      - b: \"read u8\"\n      - while b:\n          - x: \"read u8\"\n      - return b",
        )
        .unwrap_err();
        assert!(err.to_string().contains("unbounded while"), "{err}");
    }

    #[test]
    fn rejects_min_outside_while() {
        let err = compiled_with_type(
            "  T:\n    body:\n      - b: \"read u8\"\n      - acc: \"min!(b, 4)\"\n      - return acc",
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("only valid in a while bound"),
            "{err}"
        );
    }

    #[test]
    fn rejects_reserved_register_name() {
        let err = compile_text(&schema_with("      - and: u8 >0", "")).unwrap_err();
        assert!(err.to_string().contains("reserved"), "{err}");
    }

    #[test]
    fn rejects_statement_arity() {
        let err = compiled_with_type(
            "  T:\n    body:\n      - b: \"read u8\"\n      - check_mask!(b)\n      - return b",
        )
        .unwrap_err();
        assert!(err.to_string().contains("check_mask! expects"), "{err}");
    }

    #[test]
    fn constant_if_folds() {
        let skipped = compiled_with_type(
            "  T:\n    body:\n      - b: \"read u8\"\n      - if 0:\n          - x: \"read u8\"\n      - return b",
        )
        .unwrap();
        let reads = skipped.messages[0]
            .program
            .iter()
            .filter(|i| matches!(i, Instr::ReadFixed { .. }))
            .count();
        assert_eq!(reads, 1, "dead if-0 body must be folded away");

        let inlined = compiled_with_type(
            "  T:\n    body:\n      - b: \"read u8\"\n      - if 1:\n          - x: \"read u8\"\n      - return b",
        )
        .unwrap();
        let reads = inlined.messages[0]
            .program
            .iter()
            .filter(|i| matches!(i, Instr::ReadFixed { .. }))
            .count();
        assert_eq!(reads, 2, "if-1 body must be inlined without a branch");
    }

    #[test]
    fn if_compiles_forward_branch() {
        let compiled = compiled_with_type(
            "  T:\n    body:\n      - b: \"read u8\"\n      - if b:\n          - check_range!(b, 200, 255)\n      - return b",
        )
        .unwrap();
        let program = &compiled.messages[0].program;
        let branches: Vec<_> = program
            .iter()
            .filter_map(|i| match i {
                Instr::BranchIfZero { skip, .. } => Some(*skip),
                _ => None,
            })
            .collect();
        assert_eq!(branches, vec![1], "branch must skip exactly the check");
    }

    #[test]
    fn expression_temporaries_reuse_slots() {
        let compiled = compiled_with_type(
            "  T:\n    body:\n      - b: \"read u8\"\n      - a: \"(b and 0x0F) or ((b shr 4) and 0x0F)\"\n      - c: \"(a shl 1) xor b\"\n      - return c",
        )
        .unwrap();
        let program = &compiled.messages[0].program;
        assert!(!program.is_empty());
        // Preamble (2 regs) + b/a/c + temps must stay within the VM space.
        let max_reg = program
            .iter()
            .filter_map(|i| match i {
                Instr::BinOp { dst, a, b, .. } => Some([
                    *dst as usize,
                    match a {
                        Operand::Reg(r) => *r as usize,
                        Operand::Const(_) => 0,
                    },
                    match b {
                        Operand::Reg(r) => *r as usize,
                        Operand::Const(_) => 0,
                    },
                ]),
                _ => None,
            })
            .flatten()
            .max()
            .unwrap();
        assert!(max_reg < MAX_REGS, "temp leak: register {max_reg}");
    }
}
