use std::fmt::Formatter;

pub mod app;
pub mod server;

#[derive(Debug)]
enum NokError {
    IoError(std::io::Error),
    Redirect(String),
}

impl std::fmt::Display for NokError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            Self::IoError(ref e) => std::fmt::Display::fmt(e, f),
            Self::Redirect(ref url) => write!(f, "Redirect({})", url),
        }
    }
}

impl std::error::Error for NokError {}

impl From<std::io::Error> for NokError {
    fn from(e: std::io::Error) -> Self {
        Self::IoError(e)
    }
}

impl From<tokio::time::error::Elapsed> for NokError {
    fn from(e: tokio::time::error::Elapsed) -> Self {
        Self::IoError(e.into())
    }
}
