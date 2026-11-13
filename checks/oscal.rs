//! The account's OSCAL document against NIST's OSCAL 1.2.3 component-definition
//! JSON schema (`oscal_component_schema.json`, from the usnistgov/OSCAL v1.2.3
//! release). The walk checks `$ref`, `type`, `required`, `properties` with
//! `additionalProperties: false`, `items`, `minItems`, `enum`, `anyOf` and
//! `allOf`, and the patterns of the UUID, token, string, markup-line, URI and
//! date-time datatypes, written out by hand. It does not check other patterns or
//! formats, nor the metaschema's constraints (allowed values, co-occurrence),
//! which NIST's oscal-cli validates.

use serde_json::Value;

fn schema() -> Value { serde_json::from_str(include_str!("oscal_component_schema.json")).unwrap() }

/// A datatype's pattern, by its name, written out by hand.
fn datatype(name: &str, s: &str) -> Option<bool> {
    let hex = |p: &str, n: usize| p.len() == n && p.chars().all(|c| c.is_ascii_hexdigit());
    let token = |s: &str| s.chars().next().is_some_and(|c| c.is_alphabetic() || c == '_') && s.chars().all(|c| c.is_alphanumeric() || ".-_".contains(c));
    Some(match name {
        "UUIDDatatype" => {
            let p: Vec<&str> = s.split('-').collect();
            p.len() == 5 && hex(p[0], 8) && hex(p[1], 4) && hex(p[2], 4) && hex(p[3], 4) && hex(p[4], 12)
                && "45".contains(&p[2][..1]) && "89abAB".contains(&p[3][..1])
        }
        "TokenDatatype" => token(s),
        "StringDatatype" => !s.is_empty() && s.trim() == s,
        "MarkupLineDatatype" => !s.is_empty() && !s.contains('\n'),
        "URIDatatype" => s.split_once(':').is_some_and(|(scheme, rest)| !rest.is_empty() && token(scheme)),
        "DateTimeWithTimezoneDatatype" => {
            let b = s.as_bytes();
            let digits = |r: std::ops::Range<usize>| r.clone().all(|i| b.get(i).is_some_and(u8::is_ascii_digit));
            s.len() >= 20 && digits(0..4) && b[4] == b'-' && digits(5..7) && b[7] == b'-' && digits(8..10) && b[10] == b'T'
                && digits(11..13) && b[13] == b':' && digits(14..16) && b[16] == b':' && digits(17..19)
                && (s.ends_with('Z') || s[19..].trim_start_matches(|c: char| c == '.' || c.is_ascii_digit()).len() == 6)
        }
        _ => return None,
    })
}

/// Every place `v` breaks schema `s`, by its JSON path.
fn walk(defs: &Value, s: &Value, v: &Value, at: &str, errs: &mut Vec<String>) {
    if let Some(r) = s["$ref"].as_str() {
        let name = r.trim_start_matches("#/definitions/");
        if let (Some(text), Some(ok)) = (v.as_str(), v.as_str().and_then(|t| datatype(name, t))) {
            if !ok { errs.push(format!("{at}: {text:?} is not a {name}")); }
        }
        walk(defs, &defs[name], v, at, errs);
    }
    if let Some(any) = s["anyOf"].as_array() {
        if !any.iter().any(|b| { let mut e = Vec::new(); walk(defs, b, v, at, &mut e); e.is_empty() }) { errs.push(format!("{at}: matches no anyOf branch")); }
    }
    for b in s["allOf"].as_array().into_iter().flatten() { walk(defs, b, v, at, errs); }
    if let Some(t) = s["type"].as_str() {
        let ok = match t { "object" => v.is_object(), "array" => v.is_array(), "string" => v.is_string(), "integer" => v.is_i64() || v.is_u64(),
            "number" => v.is_number(), "boolean" => v.is_boolean(), _ => true };
        if !ok { errs.push(format!("{at}: not {t}")); return; }
    }
    if let Some(e) = s["enum"].as_array() { if !e.contains(v) { errs.push(format!("{at}: {v} is not one of the enum")); } }
    if let Some(o) = v.as_object() {
        for k in s["required"].as_array().into_iter().flatten().filter_map(|k| k.as_str()) {
            if !o.contains_key(k) { errs.push(format!("{at}: {k} is required")); }
        }
        let props = s["properties"].as_object();
        for (k, x) in o {
            match props.and_then(|p| p.get(k)) {
                Some(ps) => walk(defs, ps, x, &format!("{at}/{k}"), errs),
                None if s["additionalProperties"] == Value::Bool(false) => errs.push(format!("{at}: {k} is not allowed")),
                None => {}
            }
        }
    }
    if let Some(a) = v.as_array() {
        if let Some(m) = s["minItems"].as_u64() { if (a.len() as u64) < m { errs.push(format!("{at}: fewer than {m} items")); } }
        for (i, x) in a.iter().enumerate() { if s["items"].is_object() { walk(defs, &s["items"], x, &format!("{at}/{i}"), errs); } }
    }
}

fn errors(doc: &Value) -> Vec<String> {
    let s = schema();
    let mut errs = Vec::new();
    walk(&s["definitions"], &s, doc, "", &mut errs);
    errs
}

fn account() -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".bon/account.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn the_account_is_an_oscal_component_definition() {
    assert_eq!(errors(&account()), Vec::<String>::new());
}

#[test]
fn the_walk_rejects_what_the_schema_forbids() {
    let d = account();
    let plant = |f: &dyn Fn(&mut Value)| { let mut x = d.clone(); f(&mut x); assert!(!errors(&x).is_empty()); };
    plant(&|x| { x["component-definition"]["metadata"].as_object_mut().unwrap().remove("oscal-version"); });
    plant(&|x| { x["component-definition"]["metadata"]["colour"] = "blue".into(); });
    plant(&|x| { x["component-definition"]["uuid"] = "00000000-0000-1000-8000-000000000000".into(); });
    plant(&|x| { x["component-definition"]["components"] = Value::Array(Vec::new()); });
    plant(&|x| { x["component-definition"]["components"][0]["props"][0]["name"] = "not a token".into(); });
    plant(&|x| { x["component-definition"]["metadata"]["last-modified"] = "2026-11-13".into(); });
}
