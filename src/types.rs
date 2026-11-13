//! `bon types`: the types programs are built on, emitted from the kernel's
//! declarations. Trusted code. It reads the files the manifest's `[types]`
//! names in `from` and writes each target in `types`:
//!
//! ```toml
//! [types]
//! from = ["src/gates.rs"]
//! types = { typescript = "programs/kernel.ts", go = "programs/kernel/kernel.go", python = "programs/kernel.py" }
//! ```
//!
//! It emits every unindented `pub type`, `pub struct`, `pub enum` and
//! `pub const` in those files, with their `///` lines, in file order. Text
//! (`Vec<char>`) is a string; a single-field tuple struct over an integer is an
//! identity, not a quantity, and a decimal string; an enum is an object with one
//! key, its variant.

use std::path::Path;

/// One declaration, as written in a `from` file.
enum Item {
    Alias { name: String, ty: String },
    /// A single-field tuple struct over an integer: an identity, written as a decimal string.
    Identity { name: String },
    Struct { name: String, fields: Vec<Field> },
    Enum { name: String, variants: Vec<(String, Vec<Field>)> },
    Const { name: String, value: String },
}

struct Field { name: String, ty: String, doc: Vec<String> }

struct Declared { doc: Vec<String>, item: Item }

/// Split at top-level commas.
fn split(s: &str) -> Vec<String> {
    let (mut depth, mut start, mut parts) = (0i32, 0, Vec::new());
    for (i, c) in s.char_indices() {
        match c { '<' | '(' | '{' | '[' => depth += 1, '>' | ')' | '}' | ']' => depth -= 1, _ => {} }
        if c == ',' && depth == 0 { parts.push(s[start..i].trim().to_string()); start = i + 1; }
    }
    if !s[start..].trim().is_empty() { parts.push(s[start..].trim().to_string()); }
    parts
}

/// The fields of a `{ … }` body, one per line or comma, with their `///` lines.
fn fields(body: &str) -> Vec<Field> {
    let mut out = Vec::new();
    let mut doc = Vec::new();
    for line in body.lines().map(str::trim) {
        if let Some(d) = line.strip_prefix("///") { doc.push(d.trim().to_string()); continue; }
        if line.is_empty() || line.starts_with("//") || line.starts_with("#[") { continue; }
        for f in split(line) {
            let Some((name, ty)) = f.trim_start_matches("pub ").split_once(':') else { continue };
            out.push(Field { name: name.trim().trim_start_matches("r#").to_string(), ty: ty.trim().to_string(), doc: std::mem::take(&mut doc) });
        }
    }
    out
}

/// The text from the `{` at or after `at` to its matching `}`, exclusive.
fn braced(text: &str, at: usize) -> Option<(&str, usize)> {
    let open = at + text[at..].find('{')?;
    let mut depth = 0;
    for (i, c) in text[open..].char_indices() {
        if c == '{' { depth += 1; }
        if c == '}' { depth -= 1; if depth == 0 { return Some((&text[open + 1..open + i], open + i + 1)); } }
    }
    None
}

/// Every unindented declaration in one file, in order.
fn declarations(text: &str) -> Vec<Declared> {
    let mut out = Vec::new();
    let mut doc: Vec<String> = Vec::new();
    let mut offset = 0;
    for line in text.split_inclusive('\n') {
        let start = offset;
        offset += line.len();
        let l = line.trim_end();
        if let Some(d) = l.strip_prefix("///") { doc.push(d.trim().to_string()); continue; }
        if l.starts_with("#[") { continue; }
        let take = |doc: &mut Vec<String>| std::mem::take(doc);
        if let Some(rest) = l.strip_prefix("pub type ") {
            let (name, ty) = rest.split_once('=').unwrap_or((rest, ""));
            out.push(Declared { doc: take(&mut doc), item: Item::Alias { name: name.trim().into(), ty: ty.trim().trim_end_matches(';').trim().into() } });
        } else if let Some(rest) = l.strip_prefix("pub const ") {
            let (name, value) = rest.split_once('=').unwrap_or((rest, ""));
            let name = name.split(':').next().unwrap_or("").trim().to_string();
            out.push(Declared { doc: take(&mut doc), item: Item::Const { name, value: value.trim().trim_end_matches(';').trim().into() } });
        } else if let Some(rest) = l.strip_prefix("pub struct ") {
            let name: String = rest.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
            if let Some(inside) = rest[name.len()..].strip_prefix('(').and_then(|r| r.rsplit_once(')')).map(|(i, _)| i.trim().trim_start_matches("pub ").trim()) {
                // A single-field tuple struct is its own type in Rust; programs see its field:
                // an integer as a decimal string (an identity), anything else as that type.
                if ["u8", "u16", "u32", "u64", "usize", "i8", "i16", "i32", "i64", "isize"].contains(&inside) {
                    out.push(Declared { doc: take(&mut doc), item: Item::Identity { name } });
                } else {
                    out.push(Declared { doc: take(&mut doc), item: Item::Alias { name, ty: inside.to_string() } });
                }
            } else if let Some((body, _)) = braced(text, start) {
                out.push(Declared { doc: take(&mut doc), item: Item::Struct { name, fields: fields(body) } });
            }
        } else if let Some(rest) = l.strip_prefix("pub enum ") {
            let name: String = rest.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
            if let Some((body, _)) = braced(text, start) {
                let body: String = body.lines().map(str::trim).filter(|l| !l.starts_with("//") && !l.starts_with("#[")).collect::<Vec<_>>().join(" ");
                let variants = split(&body).into_iter().map(|v| match v.split_once('{') {
                    Some((tag, rest)) => (tag.trim().to_string(), fields(rest.trim_end().trim_end_matches('}'))),
                    None => (v.trim().to_string(), Vec::new()),
                }).collect();
                out.push(Declared { doc: take(&mut doc), item: Item::Enum { name, variants } });
            }
        } else if !l.trim().is_empty() {
            doc.clear();
        }
    }
    out
}

fn inner<'a>(ty: &'a str, wrapper: &str) -> Option<&'a str> {
    ty.strip_prefix(wrapper)?.strip_prefix('<')?.strip_suffix('>')
}

fn tuple(ty: &str) -> Option<Vec<String>> {
    ty.strip_prefix('(')?.strip_suffix(')').map(split)
}

fn camel(s: &str) -> String {
    s.split('_').map(|w| { let mut c = w.chars(); c.next().map_or(String::new(), |f| f.to_uppercase().chain(c).collect()) }).collect()
}

// ── TypeScript ──────────────────────────────────────────

fn ts(ty: &str) -> String {
    let ty = ty.trim();
    if ty == "Vec<char>" || ty == "String" { return "string".into(); }
    if let Some(t) = inner(ty, "Vec") { return format!("Array<{}>", ts(t)); }
    if let Some(t) = inner(ty, "Option") { return format!("{} | null", ts(t)); }
    if let Some(ts_) = tuple(ty) { return format!("[{}]", ts_.iter().map(|t| ts(t)).collect::<Vec<_>>().join(", ")); }
    match ty { "bool" => "boolean".into(), "u8" | "u16" | "u32" | "u64" | "usize" | "i8" | "i16" | "i32" | "i64" | "isize" | "f32" | "f64" => "number".into(), _ => ty.into() }
}

fn ts_doc(doc: &[String], indent: &str) -> String {
    if doc.is_empty() { String::new() } else { format!("{indent}/** {} */\n", doc.join(" ")) }
}

fn typescript(items: &[Declared], from: &str) -> String {
    let mut out = format!("// Generated from {from} by bon types. Do not edit.\n");
    for d in items {
        out += &ts_doc(&d.doc, "");
        out += &match &d.item {
            Item::Identity { name } => format!("export type {name} = string;\n"),
            Item::Alias { name, ty } => format!("export type {name} = {};\n", ts(ty)),
            Item::Const { name, value } => format!("export const {name} = {value};\n"),
            Item::Struct { name, fields } => format!("export interface {name} {{ {} }}\n",
                fields.iter().map(|f| format!("{}: {}", f.name, ts(&f.ty))).collect::<Vec<_>>().join("; ")),
            Item::Enum { name, variants } => format!("export type {name} = {};\n", variants.iter().map(|(tag, fs)| format!("{{ {}: {{ {} }} }}",
                tag.to_lowercase(), fs.iter().map(|f| format!("{}: {}", f.name, ts(&f.ty))).collect::<Vec<_>>().join("; "))).collect::<Vec<_>>().join(" | ")),
        };
    }
    out
}

// ── Go ──────────────────────────────────────────────────

fn go(ty: &str) -> String {
    let ty = ty.trim();
    if ty == "Vec<char>" || ty == "String" { return "string".into(); }
    if let Some(t) = inner(ty, "Vec") { return format!("[]{}", go(t)); }
    if let Some(t) = inner(ty, "Option") { return format!("*{}", go(t)); }
    if let Some(ts_) = tuple(ty) { return format!("Tuple{}[{}]", ts_.len(), ts_.iter().map(|t| go(t)).collect::<Vec<_>>().join(", ")); }
    match ty {
        "bool" => "bool".into(), "u8" => "uint8".into(), "u16" => "uint16".into(), "u32" => "uint32".into(),
        "u64" | "usize" => "uint64".into(), "i8" => "int8".into(), "i16" => "int16".into(), "i32" => "int32".into(),
        "i64" | "isize" => "int64".into(), "f32" => "float32".into(), "f64" => "float64".into(), _ => ty.into(),
    }
}

fn go_doc(doc: &[String], indent: &str) -> String {
    doc.iter().map(|d| format!("{indent}// {d}\n")).collect()
}

/// Struct lines as gofmt writes them: names and types in columns, aligned
/// within each run of lines that no comment interrupts.
fn go_struct(lines: &[(Vec<String>, String, String, String)]) -> String {
    let mut out = String::new();
    let mut run: Vec<&(Vec<String>, String, String, String)> = Vec::new();
    let flush = |run: &mut Vec<&(Vec<String>, String, String, String)>, out: &mut String| {
        let (w1, w2) = (run.iter().map(|l| l.1.len()).max().unwrap_or(0), run.iter().map(|l| l.2.len()).max().unwrap_or(0));
        for (_, name, ty, tag) in run.drain(..) { *out += &format!("\t{name:w1$} {ty:w2$} {tag}\n"); }
    };
    for l in lines {
        if !l.0.is_empty() { flush(&mut run, &mut out); out += &go_doc(&l.0, "\t"); }
        run.push(l);
    }
    flush(&mut run, &mut out);
    out
}

fn go_fields(fields: &[Field]) -> String {
    let lines: Vec<_> = fields.iter().map(|f| (f.doc.clone(), camel(&f.name), go(&f.ty), format!("`json:\"{}\"`", f.name))).collect();
    go_struct(&lines)
}

fn golang(items: &[Declared], from: &str, package: &str) -> String {
    let mut out = format!("// Code generated from {from} by bon types. DO NOT EDIT.\n\npackage {package}\n\nimport \"encoding/json\"\n");
    let mut arities: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
    let mut note = |fields: &[Field]| for f in fields { let mut t = f.ty.as_str(); while let Some(i) = t.find('(') { let rest = &t[i..]; if let Some(ts_) = tuple(rest.split_inclusive(')').next().unwrap_or("")) { arities.insert(ts_.len()); } t = &t[i + 1..]; } };
    for d in items {
        out += "\n";
        out += &go_doc(&d.doc, "");
        out += &match &d.item {
            Item::Identity { name } => format!("type {name} = string\n"),
            Item::Alias { name, ty } => format!("type {name} = {}\n", go(ty)),
            Item::Const { name, value } => format!("const {name} = {value}\n"),
            Item::Struct { name, fields } => {
                note(fields);
                format!("type {name} struct {{\n{}}}\n", go_fields(fields))
            }
            Item::Enum { name, variants } => {
                let mut bodies = String::new();
                let mut lines = Vec::new();
                for (tag, fs) in variants {
                    note(fs);
                    lines.push((Vec::new(), tag.clone(), format!("*{name}{tag}"), format!("`json:\"{},omitempty\"`", tag.to_lowercase())));
                    bodies += &format!("\ntype {name}{tag} struct {{\n{}}}\n", go_fields(fs));
                }
                format!("// One of its variants is set.\ntype {name} struct {{\n{}}}\n", go_struct(&lines)) + &bodies
            }
        };
    }
    for n in &arities {
        let names: Vec<String> = (0..*n).map(|i| format!("T{i}")).collect();
        let fields: Vec<String> = (0..*n).map(|i| format!("\tF{i} T{i}")).collect();
        let reads: String = (0..*n).map(|i| format!("\tif err := json.Unmarshal(raw[{i}], &t.F{i}); err != nil {{\n\t\treturn err\n\t}}\n")).collect();
        out += &format!("\n// Tuple{n} is written in JSON as a {n}-element array.\ntype Tuple{n}[{} any] struct {{\n{}\n}}\n\n\
func (t *Tuple{n}[{}]) UnmarshalJSON(b []byte) error {{\n\tvar raw [{n}]json.RawMessage\n\tif err := json.Unmarshal(b, &raw); err != nil {{\n\t\treturn err\n\t}}\n{reads}\treturn nil\n}}\n\n\
func (t Tuple{n}[{}]) MarshalJSON() ([]byte, error) {{\n\treturn json.Marshal([{n}]any{{{}}})\n}}\n",
            names.join(", "), fields.join("\n"), names.join(", "), names.join(", "), (0..*n).map(|i| format!("t.F{i}")).collect::<Vec<_>>().join(", "));
    }
    if arities.is_empty() { out += "\nvar _ = json.Marshal\n"; }
    out
}

// ── Python ──────────────────────────────────────────────

fn py(ty: &str) -> String {
    let ty = ty.trim();
    if ty == "Vec<char>" || ty == "String" { return "str".into(); }
    if let Some(t) = inner(ty, "Vec") { return format!("list[{}]", py(t)); }
    if let Some(t) = inner(ty, "Option") { return format!("{} | None", py(t)); }
    if let Some(ts_) = tuple(ty) { return format!("tuple[{}]", ts_.iter().map(|t| py(t)).collect::<Vec<_>>().join(", ")); }
    match ty { "bool" => "bool".into(), "u8" | "u16" | "u32" | "u64" | "usize" | "i8" | "i16" | "i32" | "i64" | "isize" => "int".into(), "f32" | "f64" => "float".into(), _ => ty.into() }
}

fn py_doc(doc: &[String], indent: &str) -> String {
    doc.iter().map(|d| format!("{indent}# {d}\n")).collect()
}

fn python(items: &[Declared], from: &str) -> String {
    let mut out = format!("# Generated from {from} by bon types. Do not edit.\nfrom __future__ import annotations\n\nfrom typing import TypedDict\n");
    let class = |name: &str, fields: &[Field]| -> String {
        const KEYWORDS: [&str; 6] = ["from", "import", "class", "def", "pass", "global"];
        if fields.iter().any(|f| KEYWORDS.contains(&f.name.as_str())) {
            return format!("{name} = TypedDict(\"{name}\", {{{}}})\n", fields.iter().map(|f| format!("\"{}\": {}", f.name, py(&f.ty))).collect::<Vec<_>>().join(", "));
        }
        let body: String = fields.iter().map(|f| format!("{}    {}: {}\n", py_doc(&f.doc, "    "), f.name, py(&f.ty))).collect();
        format!("class {name}(TypedDict):\n{}", if body.is_empty() { "    pass\n".into() } else { body })
    };
    for d in items {
        out += "\n";
        out += &py_doc(&d.doc, "");
        out += &match &d.item {
            Item::Identity { name } => format!("{name} = str\n"),
            Item::Alias { name, ty } => format!("{name} = {}\n", py(ty)),
            Item::Const { name, value } => format!("{name} = {value}\n"),
            Item::Struct { name, fields } => class(name, fields),
            Item::Enum { name, variants } => {
                let mut s = String::new();
                for (tag, fs) in variants { s += &class(&format!("{name}{tag}"), fs); s += "\n"; }
                s + &format!("# One key: its variant.\n{name} = TypedDict(\"{name}\", {{{}}}, total=False)\n",
                    variants.iter().map(|(tag, _)| format!("\"{}\": {name}{tag}", tag.to_lowercase())).collect::<Vec<_>>().join(", "))
            }
        };
    }
    out
}

// ── the command ─────────────────────────────────────────

/// Each declared target and its text.
pub fn targets(root: &Path, manifest: &toml::Value) -> Result<Vec<(String, String)>, String> {
    let Some(p) = manifest.get("types") else { return Ok(Vec::new()) };
    let from: Vec<String> = p.get("from").and_then(|v| v.as_array()).ok_or("[types] needs from = [the files holding the kernel's types]")?
        .iter().filter_map(|v| v.as_str().map(String::from)).collect();
    let mut items = Vec::new();
    for f in &from {
        items.extend(declarations(&std::fs::read_to_string(root.join(f)).map_err(|e| format!("{f}: {e}"))?));
    }
    let names = from.join(", ");
    let mut out = Vec::new();
    for (lang, path) in p.get("types").and_then(|v| v.as_table()).into_iter().flatten() {
        let path = path.as_str().ok_or("[types] types: each target is a path")?.to_string();
        let text = match lang.as_str() {
            "typescript" => typescript(&items, &names),
            "go" => {
                let package = Path::new(&path).parent().and_then(|d| d.file_name()).map_or("kernel".into(), |n| n.to_string_lossy().to_string());
                golang(&items, &names, &package)
            }
            "python" => python(&items, &names),
            other => return Err(format!("[types] types: no emitter for {other}; typescript, go and python are")),
        };
        out.push((path, text));
    }
    Ok(out)
}

/// `bon types`: write each target; with `--check`, fail if one differs.
pub fn run(root: &str, check: bool) -> Result<(), String> {
    let r = Path::new(root);
    let manifest: toml::Value = toml::from_str(&std::fs::read_to_string(r.join(".bon/bon.toml")).map_err(|e| format!(".bon/bon.toml: {e}"))?)
        .map_err(|e| format!(".bon/bon.toml: {e}"))?;
    let targets = targets(r, &manifest)?;
    if targets.is_empty() { println!("no [types] in .bon/bon.toml"); return Ok(()); }
    for (path, text) in targets {
        let file = r.join(&path);
        if check {
            if std::fs::read_to_string(&file).ok().as_deref() != Some(text.as_str()) {
                return Err(format!("{path} differs from the kernel's types; run bon types"));
            }
            println!("{path} matches");
        } else {
            if let Some(d) = file.parent() { std::fs::create_dir_all(d).map_err(|e| e.to_string())?; }
            std::fs::write(&file, text).map_err(|e| format!("{path}: {e}"))?;
            println!("wrote {path}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const KERNEL: &str = "verus! {\n/// A commit.\npub struct Commit(pub Vec<char>);\npub struct Hash(pub u64);\n\n/// What it is for.\n#[allow(x)]\npub enum Kind {\n    Code { goal: Commit },\n    Other { goal: Option<Commit>, out: Vec<Hash> },\n}\n\npub struct Thing {\n    /// Its commit.\n    pub commit: Commit,\n    pub pairs: Vec<(u64, bool)>,\n}\n\nimpl View for Thing {\n    pub fn not_this() {}\n}\npub const NONE: i32 = -1;\n}\n";

    #[test]
    fn every_target_reads_the_same_declarations() {
        let items = declarations(KERNEL);
        assert_eq!(items.len(), 5);
        let t = typescript(&items, "k.rs");
        assert!(t.contains("/** A commit. */\nexport type Commit = string;"), "{t}");
        assert!(t.contains("export type Hash = string;"), "{t}");
        assert!(t.contains("export type Kind = { code: { goal: Commit } } | { other: { goal: Commit | null; out: Array<Hash> } };"), "{t}");
        assert!(t.contains("export interface Thing { commit: Commit; pairs: Array<[number, boolean]> }"), "{t}");
        assert!(t.contains("export const NONE = -1;"), "{t}");
        let g = golang(&items, "k.rs", "kernel");
        assert!(g.contains("\tCode  *KindCode  `json:\"code,omitempty\"`\n\tOther *KindOther `json:\"other,omitempty\"`"), "{g}");
        assert!(g.contains("\t// Its commit.\n\tCommit Commit                 `json:\"commit\"`\n\tPairs  []Tuple2[uint64, bool] `json:\"pairs\"`"), "{g}");
        let p = python(&items, "k.rs");
        assert!(p.contains("Kind = TypedDict(\"Kind\", {\"code\": KindCode, \"other\": KindOther}, total=False)"), "{p}");
        assert!(p.contains("    goal: Commit | None\n"), "{p}");
    }
}
