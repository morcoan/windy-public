use eframe::NativeOptions;
use egui::ViewportBuilder;
use tracing_subscriber::EnvFilter;

mod app;
mod disasm;
mod ir;
mod loader;
mod llm;
mod project;
mod ui;

fn main() -> eframe::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let options = NativeOptions {
        viewport: ViewportBuilder::default()
            .with_inner_size([1280.0, 900.0])
            .with_title("Windy"),
        ..Default::default()
    };

    eframe::run_native(
        "Windy",
        options,
        Box::new(|cc| Ok(Box::new(app::App::new(cc)))),
    )
}
