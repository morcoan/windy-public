#[cfg(feature = "beta")]
pub const PRODUCT_ID: &str = "windy-beta";
#[cfg(not(feature = "beta"))]
pub const PRODUCT_ID: &str = "windy";

#[cfg(feature = "beta")]
pub const PRODUCT_TITLE: &str = "Windy Beta";
#[cfg(not(feature = "beta"))]
pub const PRODUCT_TITLE: &str = "Windy";

#[cfg(feature = "beta")]
pub const CHANNEL: &str = "private-beta";
#[cfg(not(feature = "beta"))]
pub const CHANNEL: &str = "public";

#[cfg(feature = "beta")]
pub const VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "-beta.local");
#[cfg(not(feature = "beta"))]
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(feature = "beta")]
pub const DESCRIPTION: &str = "Private local fast-iteration PE reverse-engineering and MCP build";
#[cfg(not(feature = "beta"))]
pub const DESCRIPTION: &str = "Agent-first static Windows PE analysis MCP server";
