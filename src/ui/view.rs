#[derive(Clone, Debug, PartialEq, Eq)]
pub enum View {
    // Triage panels (Phase 1)
    Headers,
    Sections,
    Imports,
    Exports,
    Strings,
    RichHeader,
    Authenticode,
    OverlayAnomalies,

    // Code browser panels (platform phase)
    FunctionTree,
    Disassembly,
    Xrefs,
    Hex,

    Console,
}

impl View {
    pub fn title(&self) -> &'static str {
        match self {
            View::Headers => "Headers",
            View::Sections => "Sections",
            View::Imports => "Imports",
            View::Exports => "Exports",
            View::Strings => "Strings",
            View::RichHeader => "Rich Header",
            View::Authenticode => "Authenticode",
            View::OverlayAnomalies => "Overlay & Anomalies",
            View::FunctionTree => "Functions",
            View::Disassembly => "Disassembly",
            View::Xrefs => "Xrefs",
            View::Hex => "Hex",
            View::Console => "Console",
        }
    }
}
