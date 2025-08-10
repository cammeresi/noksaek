use std::io;
use std::net::SocketAddr;

use async_trait::async_trait;
use handlebars::Handlebars;
use tokio::io::AsyncWrite;

use linker_set::*;

pub type BoxApplication = Box<dyn Application + Send + Sync>;
pub type ResultApplication = io::Result<(String, BoxApplication)>;

set_declare!(apps, &'static dyn RegisterApplication);

macro_rules! register_application {
    ($name:literal, $ty:ident) => {
        paste::paste! {
            struct [<Register $ty>];

            impl RegisterApplication for [<Register $ty>] {
                fn start(&self) -> ResultApplication {
                    Ok((String::from($name), Box::new($ty::new())))
                }
            }

            #[set_entry(apps)]
            static __REGISTER_APP__: &'static dyn RegisterApplication =
                &[<Register $ty>];
        }
    };
}

pub mod hello;
pub mod random;
pub mod version;

pub trait RegisterApplication: Sync {
    fn start(&self) -> ResultApplication;
}

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
