//! Emit program types from the kernel declarations. This entry point is the
//! only translation boundary; programs never maintain a second kernel model.
fn main() {
    fn split(s: &str) -> Vec<&str> {
        let mut depth = 0i32;
        let mut start = 0;
        let mut parts = Vec::new();
        for (i, c) in s.char_indices() {
            match c { '<' | '(' | '{' => depth += 1, '>' | ')' | '}' => depth -= 1, _ => {} }
            if c == ',' && depth == 0 { parts.push(s[start..i].trim()); start = i + 1; }
        }
        if !s[start..].trim().is_empty() { parts.push(s[start..].trim()); }
        parts
    }
    fn ty(s: &str) -> String {
        let s = s.trim();
        if s == "Vec<char>" { return "string".into(); }
        if let Some(t) = s.strip_prefix("Vec<").and_then(|t| t.strip_suffix('>')) { return format!("Array<{}>", ty(t)); }
        if let Some(t) = s.strip_prefix("Option<").and_then(|t| t.strip_suffix('>')) { return format!("{} | null", ty(t)); }
        if s.starts_with('(') { return format!("[{}]", split(&s[1..s.len()-1]).iter().map(|t| ty(t)).collect::<Vec<_>>().join(", ")); }
        match s { "bool" => "boolean".into(), "u64" | "i64" | "usize" => "number".into(), _ => s.into() }
    }
    fn fields(s: &str) -> String {
        split(s).iter().map(|f| {
            let (name, t) = f.trim_start_matches("pub ").split_once(':').expect("kernel field");
            // Kernel JSON emits output hashes as decimal strings.
            let t = if name == "out" { "Array<string>".into() } else { ty(t) };
            format!("{name}: {t}")
        }).collect::<Vec<_>>().join("; ")
    }
    let source = include_str!("../src/gates.rs");
    let source = source.lines().filter(|l| !l.trim_start().starts_with("//")).collect::<Vec<_>>().join("\n");
    println!("// Generated from src/gates.rs by cargo run --example types. Do not edit.");
    let source = source.split("// ── conversions").next().unwrap_or(&source);
    // Stop before conversion functions: only the executable data declarations.
    let source = source.split("pub open spec fn paths").next().unwrap();
    for part in source.split("pub ").skip(1) {
        if let Some(rest) = part.strip_prefix("type ") {
            let (name, t) = rest.split_once('=').expect("kernel alias");
            println!("export type {} = {};", name.trim(), ty(t.split(';').next().unwrap()));
        }
    }
    for name in ["AgentProcess", "Kind", "Candidate", "Search"] {
        let key = format!("pub {} {name} {{", if name == "Kind" { "enum" } else { "struct" });
        let rest = source.split_once(&key).expect("kernel declaration").1;
        let mut depth = 1;
        let end = rest.char_indices().find_map(|(i, c)| { if c == '{' { depth += 1; } if c == '}' { depth -= 1; } (depth == 0).then_some(i) }).expect("kernel body");
        let body = &rest[..end];
        if name == "Kind" {
            let variants = split(body).iter().map(|v| {
                let (tag, body) = v.split_once('{').expect("kernel variant");
                format!("{{ {}: {{ {} }} }}", tag.trim().to_lowercase(), fields(body.trim().trim_end_matches('}')))
            }).collect::<Vec<_>>().join(" | ");
            println!("export type {name} = {variants};");
        } else { println!("export interface {name} {{ {} }}", fields(body)); }
    }
}
