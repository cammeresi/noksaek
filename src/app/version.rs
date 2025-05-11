use std::collections::HashMap;
use std::io::Error;

use tokio::io::AsyncWriteExt;

use super::*;

const TEMPLATE_NAME: &str = "app::version";
const TEMPLATE_TEXT: &str = "# Version\r\n\
                             {{git-hash}}\r\n";

register_application!("version", Version);

struct Version;

impl Version {
    fn new() -> Self {
        Version
    }

    fn generate(&self, tmpl: &Handlebars) -> io::Result<String> {
        let mut map = HashMap::new();
        map.insert("git-hash", env!("BUILD_GIT_HASH").to_string());
        match tmpl.render(TEMPLATE_NAME, &map) {
            Ok(s) => Ok(s),
            Err(e) => Err(Error::other(format!("template error: {e:?}"))),
        }
    }
}

#[async_trait]
impl Application for Version {
    fn init(&mut self, tmpl: &mut Handlebars) -> io::Result<()> {
        tmpl.register_template_string(TEMPLATE_NAME, TEMPLATE_TEXT)
            .expect("template parse error");
        Ok(())
    }

    async fn run(
        &self, _args: &[String],
        mut stream: Box<&mut (dyn AsyncWrite + Send + Unpin)>,
        _peer: &SocketAddr, tmpl: &Handlebars,
    ) -> io::Result<u64> {
        let out = self.generate(tmpl)?;
        let bytes = out.as_bytes();
        stream.write_all(bytes).await?;
        Ok(bytes.len().try_into().unwrap_or_default())
    }
}
