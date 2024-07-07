use super::*;
use tokio::io::BufReader;

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
