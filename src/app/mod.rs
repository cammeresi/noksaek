use std::io;
use std::net::SocketAddr;

use async_trait::async_trait;
use handlebars::Handlebars;
use tokio::io::AsyncWrite;

use linker_set::*;

pub type BoxApplication = Box<dyn Application + Send + Sync>;
pub type ResultApplication = io::Result<(String, BoxApplication)>;
pub type RegisterApplication = fn() -> ResultApplication;

set_declare!(apps, RegisterApplication);

macro_rules! register_application {
    ($name:literal, $ty:ident) => {
        paste::paste! {
            #[allow(non_snake_case)]
            fn [<__register_ $ty __>]() -> ResultApplication {
                Ok((String::from($name), Box::new($ty::new())))
            }

            #[set_entry(apps)]
            static __REGISTER_APP__: RegisterApplication =
                [<__register_ $ty __>];
        }
    };
}

pub mod hello;
pub mod random;
pub mod version;

#[async_trait]
pub trait Application {
    fn init(&mut self, tmpl: &mut Handlebars) -> io::Result<()>;

    /// returns number of bytes written
    async fn run(
        &self, args: &[String],
        stream: Box<&mut (dyn AsyncWrite + Send + Unpin)>, peer: &SocketAddr,
        tmpl: &Handlebars,
    ) -> io::Result<u64>;
}
