use tokio::io::AsyncWriteExt;

use super::*;

register_application!("hello", Hello);

struct Hello;

impl Hello {
    fn new() -> Self {
        Hello
    }
}

#[async_trait]
impl Application for Hello {
    fn init(&mut self, _tmpl: &mut Handlebars) -> io::Result<()> {
        Ok(())
    }

    async fn run(
        &self, _args: &[String],
        mut stream: Box<&mut (dyn AsyncWrite + Send + Unpin)>,
        _peer: &SocketAddr, _tmpl: &Handlebars,
    ) -> io::Result<u64> {
        let bytes = "Hello world!\n".as_bytes();
        stream.write_all(bytes).await?;
        Ok(bytes.len().try_into().unwrap_or_default())
    }
}
