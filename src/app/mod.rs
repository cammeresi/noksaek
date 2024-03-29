use std::io;
use std::net::SocketAddr;

use async_trait::async_trait;
use handlebars::Handlebars;
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;

use linkerset::*;

pub type BoxApplication = Box<dyn Application + Send + Sync>;
pub type ResultApplication = io::Result<(String, BoxApplication)>;
pub type RegisterApplication = fn() -> ResultApplication;

set_declare!(apps, RegisterApplication);

macro_rules! register_application {
    ($func:ident) => {
        #[set_entry(apps)]
        static __REGISTER_APP__: RegisterApplication = $func;
    };
}

pub mod random;

#[async_trait]
pub trait Application {
    fn init(&mut self, tmpl: &mut Handlebars) -> io::Result<()>;

    /// returns number of bytes written
    async fn run(
        &self, args: &[String], stream: &mut TlsStream<TcpStream>,
        peer: &SocketAddr, tmpl: &Handlebars,
    ) -> io::Result<u64>;
}
