use super::*;
use tokio::io::BufReader;
use tokio::runtime::Runtime;

#[test]
fn test_vec_capacity() {
    const SIZE: usize = 128;
    let mut buf = Vec::<u8>::with_capacity(SIZE);
    let s = buf.spare_capacity_mut();
    assert!(s.len() >= SIZE);
}

#[test]
fn test_read_request() {
    const REQUEST: &str = "gemini://example.org/foo/bar/baz\r\n";
    let mut stream = BufReader::new(REQUEST.as_bytes());
    Runtime::new().unwrap().block_on(async move {
        let r = &REQUEST[..REQUEST.len() - 2];
        assert_eq!(NsCtx::read_request(&mut stream).await.unwrap(), r);
    });
}
