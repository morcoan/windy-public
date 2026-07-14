//! Best-effort C++ symbol demangling.
//!
//! Tries MSVC decoration first (most Windows PDB symbols), then the Itanium
//! scheme used by GCC/Clang. If neither succeeds the original raw name is
//! preserved.

/// Demangle a raw linker/PDB symbol name into something readable by the LLM.
/// Returns `None` if the name is already readable or no demangler matched.
pub fn demangle(name: &str) -> Option<String> {
    // Preserve import prefix if present.  A C++ DLL export can be exported
    // under its decorated name, producing `__imp_?foo@@...` in the IAT.
    let (prefix, body) = if let Some(body) = name.strip_prefix("__imp_") {
        ("__imp_", body)
    } else {
        ("", name)
    };

    // Fast path: nothing to do for names that cannot be C++ decorated.
    if body.is_empty() || looks_plain(body) {
        return None;
    }

    if let Some(d) = demangle_msvc(body)
        && d != body
    {
        return Some(format!("{prefix}{d}"));
    }

    if let Some(d) = demangle_itanium(body)
        && d != body
    {
        return Some(format!("{prefix}{d}"));
    }

    None
}

/// Return the best readable name: demangled if possible, otherwise the raw name.
pub fn demangle_or_raw(name: &str) -> String {
    demangle(name).unwrap_or_else(|| name.to_string())
}

fn looks_plain(name: &str) -> bool {
    // MSVC decorated names begin with `?` or `_`; Itanium with `_Z`.
    // Everything else we leave alone (plain C/API names, ordinals, etc.).
    !name.starts_with('?') && !name.starts_with('_')
}

fn demangle_msvc(name: &str) -> Option<String> {
    let flags = msvc_demangler::DemangleFlags::llvm();
    msvc_demangler::demangle(name, flags).ok()
}

fn demangle_itanium(name: &str) -> Option<String> {
    cpp_demangle::Symbol::new(name.as_bytes())
        .ok()
        .and_then(|s| s.demangle().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msvc_function_demangles() {
        // int foo(int,int)
        let raw = "?foo@@YAHHH@Z";
        let d = demangle(raw).expect("should demangle");
        assert!(d.contains("foo"), "{d}");
        // MSVC-style 'int' may render as `int`.
    }

    #[test]
    fn itanium_function_demangles() {
        let raw = "_ZN5space3fooEi";
        assert_eq!(demangle(raw).unwrap(), "space::foo(int)");
    }

    #[test]
    fn plain_names_passthrough() {
        assert_eq!(demangle("CreateFileW"), None);
        assert_eq!(demangle("__imp_CreateFileW"), None);
    }
}
