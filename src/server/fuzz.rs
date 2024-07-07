use super::*;
use libfuzzer_sys::arbitrary::{Arbitrary, Unstructured};
use std::pin::*;
use std::task::Poll;
use tokio::io::ReadBuf;
use tokio::runtime::Runtime;

struct FuzzStream<R> {
    read: R,
}

impl<R> FuzzStream<R> {
    fn new(read: R) -> Self {
        Self { read }
    }
}

impl<R> AsyncRead for FuzzStream<R>
where
    R: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>, ctx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        pin!(&mut self.read).as_mut().poll_read(ctx, buf)
    }
}

impl<R> AsyncWrite for FuzzStream<R> {
    fn poll_write(
        self: Pin<&mut Self>, _ctx: &mut std::task::Context<'_>, buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: Pin<&mut Self>, _ctx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>, _ctx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }
}

fn root() -> String {
    std::env::var("NOK_ROOT").expect("set NOK_ROOT for fuzzing")
}

fn random_peer(data: &mut Unstructured) -> SocketAddr {
    SocketAddr::new(
        IpAddr::V6(Ipv6Addr::new(
            u16::arbitrary(data).unwrap(),
            u16::arbitrary(data).unwrap(),
            u16::arbitrary(data).unwrap(),
            u16::arbitrary(data).unwrap(),
            u16::arbitrary(data).unwrap(),
            u16::arbitrary(data).unwrap(),
            u16::arbitrary(data).unwrap(),
            u16::arbitrary(data).unwrap(),
        )),
        u16::arbitrary(data).unwrap(),
    )
}

fn random_vhost<'a>(ctx: &'a NsCtx, data: &mut Unstructured) -> &'a VhostCtx {
    let vhosts = ctx.vhosts.values().collect::<Vec<_>>();
    let x = usize::arbitrary(data).unwrap();
    vhosts[x % vhosts.len()]
}

fn take_rest(data: Unstructured) -> FuzzStream<&[u8]> {
    FuzzStream::new(<&[u8] as Arbitrary>::arbitrary_take_rest(data).unwrap())
}

pub fn handle(data: &[u8]) {
    let mut ctx = NsCtx::new(0);
    ctx.init_walk(&root()).ok();

    let rt = Runtime::new().unwrap();
    rt.block_on(async move {
        let mut data = Unstructured::new(data);
        let peer = random_peer(&mut data);
        let vhost = random_vhost(&ctx, &mut data);
        let mut data = take_rest(data);

        ctx.handle(&vhost, &mut data, &peer).await;
    });
}

pub fn accepted(data: &[u8]) {
    let mut ctx = NsCtx::new(0);
    ctx.init_walk(&root()).ok();

    let rt = Runtime::new().unwrap();
    rt.block_on(async move {
        let mut data = Unstructured::new(data);
        let peer = random_peer(&mut data);
        let data = take_rest(data);

        ctx.accepted(FuzzStream::new(data), peer).await;
    });
}
