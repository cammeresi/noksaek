use std::marker::Unpin;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::task::{Context, Poll};
use std::time::Instant;

use tokio::io::BufReader;

use super::*;

const ROOT: &str = "testroot";
const HOST: &str = "example.org";
const CLIENT: SocketAddr =
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), DEFAULT_PORT);
const TEST_TIMEOUT: Duration = Duration::from_secs(1);
const RC_OK: &str = "20 text/gemini";

struct TestVhostCtx {
    name: String,
    rootdir: PathBuf,
}

impl Certificate for TestVhostCtx {
    fn name(&self) -> &str {
        &self.name
    }

    fn root(&self) -> &PathBuf {
        &self.rootdir
    }

    fn get_cert(
        &self,
    ) -> (Vec<CertificateDer<'static>>, PrivateSec1KeyDer<'static>) {
        unimplemented!();
    }
}

struct DelayedReader<T> {
    inner: T,
    first: bool,
    delay: Duration,
    ready: Arc<AtomicBool>,
}

impl<T> DelayedReader<T> {
    fn new(inner: T, delay: Duration) -> Self {
        Self {
            inner,
            first: true,
            delay,
            ready: AtomicBool::new(false).into(),
        }
    }
}

impl<T> AsyncRead for DelayedReader<T>
where
    T: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.first {
            self.first = false;
            let waker = cx.waker().clone();
            let delay = self.delay;
            let ready = self.ready.clone();
            tokio::task::spawn(async move {
                tokio::time::sleep(delay).await;
                ready.store(true, Ordering::Release);
                waker.wake();
            });
            Poll::Pending
        } else if !self.ready.load(Ordering::Acquire) {
            // executor can re-poll before we say we're ready
            Poll::Pending
        } else {
            T::poll_read(Pin::new(&mut self.inner), cx, buf)
        }
    }
}

#[test]
fn test_vec_capacity() {
    const SIZE: usize = 128;
    let mut buf = Vec::<u8>::with_capacity(SIZE);
    let s = buf.spare_capacity_mut();
    assert!(s.len() >= SIZE);
}

#[tokio::test]
async fn test_read_request() {
    const REQUEST: &str = "gemini://example.org/foo/bar/baz\r\n";
    let mut stream = BufReader::new(REQUEST.as_bytes());
    let r = &REQUEST[..REQUEST.len() - 2];
    assert_eq!(
        NsCtx::<TestVhostCtx>::read_request(&mut stream)
            .await
            .unwrap(),
        r
    );
}

fn create_server() -> NsCtx<TestVhostCtx> {
    let mut ctx = NsCtx::<TestVhostCtx>::new(DEFAULT_PORT, TEST_TIMEOUT);
    ctx.add_host(
        HOST.into(),
        TestVhostCtx {
            name: HOST.into(),
            rootdir: ROOT.to_string().into(),
        },
    );
    ctx
}

// returns (status line, rest of the bytes)
async fn run_request(
    ctx: &NsCtx<TestVhostCtx>, vhost: &TestVhostCtx, req: &str,
) -> (String, Vec<u8>) {
    let mut out = Vec::new();
    ctx.handle(vhost, &mut req.as_bytes(), &mut out, &CLIENT)
        .await;
    let mut status = String::new();
    let len = out
        .as_slice()
        .read_line(&mut status)
        .await
        .expect("failed to read status");
    out.drain(0..len);
    (status, out)
}

async fn test_request(req: &str, status: &str, output: &str) {
    let ctx = create_server();
    let vhost = ctx.get_host(HOST);
    let (s, o) = run_request(&ctx, vhost, req).await;
    let len = s.len();
    assert_eq!(status, &s[..len - 2]);
    assert_eq!("\r\n", &s[len - 2..]);
    assert_eq!(output, String::from_utf8(o).unwrap());
}

#[tokio::test]
async fn test_root() {
    const REQ: &str = "gemini://example.org/\r\n";
    test_request(REQ, RC_OK, "aaa\n").await;
}

#[tokio::test]
async fn test_directory() {
    const REQ: &str = "gemini://example.org/foo/\r\n";
    test_request(REQ, RC_OK, "bbbb\n").await;
}

#[tokio::test]
async fn test_file() {
    const REQ: &str = "gemini://example.org/foo/bar.gmi\r\n";
    test_request(REQ, RC_OK, "ccccc\n").await;
}

#[tokio::test]
async fn test_redirect() {
    const REQ: &str = "gemini://example.org/foo\r\n";
    test_request(REQ, "31 /foo/", "").await;
}

#[tokio::test]
async fn test_err_not_found() {
    const REQ: &str = "gemini://example.org/fooo\r\n";
    test_request(REQ, ERR_NOT_FOUND, "").await;
}

#[tokio::test]
async fn test_err_bad_request() {
    const REQ: &str = "asdf";
    test_request(REQ, ERR_BAD_REQUEST, "").await;
}

#[tokio::test]
async fn test_app() {
    const REQ: &str = "gemini://example.org/stuff/hello\r\n";
    test_request(REQ, RC_OK, "Hello world!\n").await;
}

#[tokio::test]
async fn test_gpp() {
    const REQ: &str = "gemini://example.org/pre.gmi\r\n";
    test_request(REQ, RC_OK, "aaa bbb ccc\r\n").await;
}

#[tokio::test]
async fn test_delayed_reader() {
    const AAA: &str = "aaa";
    const DELAY: Duration = TEST_TIMEOUT;
    let mut reader = DelayedReader::new(AAA.as_bytes(), DELAY);
    let mut buf = Vec::new();
    let start = Instant::now();
    reader.read_buf(&mut buf).await.unwrap();
    assert_eq!(AAA, String::from_utf8(buf).unwrap());
    assert!(start.elapsed() > DELAY / 2);
    assert!(start.elapsed() < DELAY * 2);
}
