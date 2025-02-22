use criterion::{Criterion, criterion_group, criterion_main};

fn bench_read_request(c: &mut Criterion) {
    use noksaek::server::{NsCtx, VhostCtx};
    use tokio::io::BufReader;
    use tokio::runtime::Runtime;

    c.bench_function("read_request", |b| {
        b.to_async(Runtime::new().unwrap()).iter(|| async {
            const REQUEST: &str = "gemini://example.org/foo/bar/baz\r\n";
            let mut stream = BufReader::new(REQUEST.as_bytes());
            NsCtx::<VhostCtx>::read_request(&mut stream).await
        });
    });
}

criterion_group!(benches, bench_read_request);
criterion_main!(benches);
