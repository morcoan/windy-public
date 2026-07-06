#[derive(Clone, Debug, PartialEq, Eq)]
pub enum View {
    Headers,
    Sections,
    Imports,
    Exports,
    Strings,
    RichHeader,
    Authenticode,
    OverlayAnomalies,
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
            View::Console => "Console",
        }
    }
}
