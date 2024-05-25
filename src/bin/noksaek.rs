use clap::Parser;
use noksaek::server::DEFAULT_PORT;

#[derive(Parser)]
#[command(version, about)]
struct Args {
    #[arg(long, value_name = "PORT", default_value_t = DEFAULT_PORT)]
    port: u16,

    #[arg(long, value_name = "DOCROOT")]
    root: String,

    #[arg(long, value_name = "LOGDIR")]
    logdir: Option<String>,

    #[arg(long, value_name = "USERNAME")]
    setuid: Option<String>,

    #[arg(long, default_value_t = false)]
    chroot: bool,
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let args = Args::parse();
    noksaek::server::main(
        args.port,
        args.root,
        args.logdir,
        args.setuid,
        args.chroot,
    )
    .await
}
