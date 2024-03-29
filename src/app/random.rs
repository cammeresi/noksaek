use std::collections::HashMap;
use std::io::{Error, ErrorKind};

use rand::Rng;
use tokio::io::AsyncWriteExt;

use super::*;

const TEMPLATE_NAME: &str = "app::random";
const TEMPLATE_TEXT: &str = "# Random data!\r\n\
                             ```data\r\n\
                             * u8  - {{u8-dec}} - {{u8-hex}}\r\n\
                             * u16 - {{u16-dec}} - {{u16-hex}}\r\n\
                             * u32 - {{u32-dec}} - {{u32-hex}}\r\n\
                             * u64 - {{u64-dec}} - {{u64-hex}}\r\n\
                             ```\r\n";

struct Random {}

impl Random {
    fn new() -> Self {
        Random {}
    }

    fn data() -> HashMap<&'static str, String> {
        let mut rng = rand::thread_rng();
        let mut map = HashMap::new();
        let x = rng.gen::<u8>();
        map.insert("u8-dec", format!("{:20}", x));
        map.insert("u8-hex", format!("{:02x}", x));
        let x = rng.gen::<u16>();
        map.insert("u16-dec", format!("{:20}", x));
        map.insert("u16-hex", format!("{:04x}", x));
        let x = rng.gen::<u32>();
        map.insert("u32-dec", format!("{:20}", x));
        map.insert("u32-hex", format!("{:08x}", x));
        let x = rng.gen::<u64>();
        map.insert("u64-dec", format!("{:20}", x));
        map.insert("u64-hex", format!("{:016x}", x));
        map
    }

    fn gen(&self, tmpl: &Handlebars) -> io::Result<String> {
        let map = Self::data();
        match tmpl.render(TEMPLATE_NAME, &map) {
            Ok(s) => Ok(s),
            Err(e) => Err(Error::new(
                ErrorKind::Other,
                format!("template error: {:?}", e),
            )),
        }
    }
}

#[async_trait]
impl Application for Random {
    fn init(&mut self, tmpl: &mut Handlebars) -> io::Result<()> {
        tmpl.register_template_string(TEMPLATE_NAME, TEMPLATE_TEXT)
            .expect("template parse error");
        Ok(())
    }

    async fn run(
        &self, _args: &[String], stream: &mut TlsStream<TcpStream>,
        _peer: &SocketAddr, tmpl: &Handlebars,
    ) -> io::Result<u64> {
        let out = self.gen(tmpl)?;
        let bytes = out.as_bytes();
        stream.write_all(bytes).await?;
        Ok(bytes.len().try_into().unwrap_or_default())
    }
}

register_application!(register);

fn register() -> ResultApplication {
    Ok((String::from("random"), Box::new(Random::new())))
}
