use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::io::{self, Error};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use regex::Regex;
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, PrivateSec1KeyDer},
    server::ServerConfig,
};
use rustls_pemfile::{certs, ec_private_keys};
use tokio::fs::{self, File};
use tokio::io::{
    AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, ErrorKind,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_rustls::server::TlsStream;
use tokio_rustls::{rustls, LazyConfigAcceptor};
use tokio_utils::MultiRateLimiter;
use url::Url;

// https://github.com/rustls/tokio-rustls/blob/main/examples/server.rs
// https://docs.rs/rustls/latest/rustls/index.html

pub const DEFAULT_PORT: u16 = 1965;
const DEFAULT_FILENAME: &str = "index.gmi";
const GPP_SUFFIX: &str = ".master.gmi";

const TIMEOUT: Duration = Duration::from_secs(5);
const IP_RATE_LIMIT_MS: u64 = 100; // 10 per sec
const GLOBAL_RATE_LIMIT_MS: u64 = 10; // 100 per sec

struct VhostCtx {
    name: String,
    certs: Vec<CertificateDer<'static>>,
    key: PrivateSec1KeyDer<'static>,
    root: PathBuf,
}

impl VhostCtx {
    fn get_cert(
        &self,
    ) -> (Vec<CertificateDer<'static>>, PrivateSec1KeyDer<'static>) {
        (self.certs.clone(), self.key.clone_key())
    }
}

struct NsCtx {
    port: u16,
    vhosts: HashMap<String, VhostCtx>,
    tag_re: Regex,
    img_re: Regex,
    ext_re: Regex,
    ip_limit: MultiRateLimiter<Ipv6Addr>,
    global_limit: MultiRateLimiter<()>,
}

impl Debug for NsCtx {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "NsCtx")
    }
}

impl NsCtx {
    fn new(port: u16) -> Self {
        Self {
            port,
            vhosts: HashMap::new(),
            tag_re: Regex::new(r"\[\[([^\[\]]+)\]\]").unwrap(),
            img_re: Regex::new(r"^=> ([^: ]+\.(gif|jpg|png|asc|pdf)) (.*)$")
                .unwrap(),
            ext_re: Regex::new(r"^(.*)\.([^\.]+)$").unwrap(),
            ip_limit: MultiRateLimiter::new(Duration::from_millis(
                IP_RATE_LIMIT_MS,
            )),
            global_limit: MultiRateLimiter::new(Duration::from_millis(
                GLOBAL_RATE_LIMIT_MS,
            )),
        }
    }

    fn read_file(p: PathBuf) -> io::Result<io::BufReader<std::fs::File>> {
        Ok(io::BufReader::new(std::fs::File::open(p)?))
    }

    fn add_host(
        &mut self, host: String, certs: Vec<CertificateDer<'static>>,
        key: PrivateSec1KeyDer<'static>, root: PathBuf,
    ) {
        log::info!("adding vhost {}", host);
        self.vhosts.insert(
            host.clone(),
            VhostCtx {
                name: host,
                certs,
                key,
                root,
            },
        );
    }

    fn init_walk(&mut self, root: &str) -> io::Result<()> {
        const CERTS_DIR: &str = "certificates";
        const CERT: &str = "cert.pem";
        const KEY: &str = "key.pem";

        let mut dir = PathBuf::from(root);
        dir.push(CERTS_DIR);

        let dir = std::fs::read_dir(dir)?;
        for f in dir {
            let f = f?;
            if !f.file_type()?.is_dir() {
                continue;
            }
            let host = f.file_name().into_string().unwrap();
            let mut path = [root, CERTS_DIR, &host, CERT];
            let p = path.iter().collect::<PathBuf>();
            let c = certs(&mut Self::read_file(p)?)
                .map(|x| x.unwrap())
                .collect::<Vec<_>>();
            path[3] = KEY;
            let p = path.iter().collect::<PathBuf>();
            let k = ec_private_keys(&mut Self::read_file(p)?)
                .next()
                .expect("no key")?;

            let content = [&host];
            self.add_host(host.clone(), c, k, content.iter().collect());
        }
        Ok(())
    }

    async fn setup(
        &self, stream: TcpStream,
    ) -> io::Result<(TlsStream<TcpStream>, &VhostCtx)> {
        let acceptor = LazyConfigAcceptor::new(
            rustls::server::Acceptor::default(),
            stream,
        );
        tokio::pin!(acceptor);

        let start = acceptor.as_mut().await?;
        let hello = start.client_hello();
        let Some(server) = hello.server_name() else {
            return Err(Error::new(ErrorKind::InvalidData, "no server name"));
        };

        let Some(vhost) = self.vhosts.get(server) else {
            return Err(Error::new(ErrorKind::InvalidInput, "unknown vhost"));
        };
        let (cert, key) = vhost.get_cert();
        let key = PrivateKeyDer::Sec1(key);
        let cfg = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert, key)
            .expect("bad cert/key");
        let stream = start.into_stream(Arc::new(cfg)).await?;
        Ok((stream, vhost))
    }

    async fn read_request(
        &self, stream: &mut TlsStream<TcpStream>,
    ) -> io::Result<String> {
        let mut buf = [0; 1024 + 2];
        let mut read = 0;
        while read < buf.len() {
            let n = stream.read(&mut buf[read..]).await?;
            read += n;
            if n == 0 || read >= 2 && buf[read - 2..read] == [13, 10] {
                break;
            }
        }

        if read < 2 {
            return Err(Error::new(ErrorKind::InvalidInput, "no request"));
        } else if buf[read - 2..read] != [13, 10] {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "request too long",
            ));
        }

        match String::from_utf8(buf[..read - 2].to_vec()) {
            Ok(s) => Ok(s),
            Err(_) => Err(Error::new(ErrorKind::InvalidInput, "invalid utf8")),
        }
    }

    fn parse_request(
        &self, vhost: &VhostCtx, request: &str,
    ) -> io::Result<Vec<String>> {
        let Ok(url) = Url::parse(&request) else {
            return Err(Error::new(ErrorKind::InvalidInput, "invalid url"));
        };
        if url.scheme() != "gemini" {
            return Err(Error::new(ErrorKind::InvalidInput, "url scheme"));
        }
        if let Some(host) = url.host_str() {
            if host != &vhost.name {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "wrong hostname",
                ));
            }
        }
        let port = url.port().unwrap_or(DEFAULT_PORT);
        if port != self.port {
            return Err(Error::new(ErrorKind::InvalidInput, "wrong port"));
        }
        let segs = match url.path_segments() {
            None => Ok(Vec::new()),
            Some(path) => path
                .map(|x| urlencoding::decode(x))
                .collect::<Result<Vec<_>, _>>(),
        };
        match segs {
            Err(_) => {
                Err(Error::new(ErrorKind::InvalidInput, "decode failure"))
            }
            Ok(segs) => Ok(segs.iter().map(|x| x.to_string()).collect()),
        }
    }

    async fn test_file(&self, fs_path: &mut PathBuf, name: &str) -> bool {
        fs_path.push(name);
        if let Ok(f) = fs::metadata(&fs_path).await {
            if f.is_file() {
                return true;
            }
        }
        fs_path.pop();

        if name.ends_with(".gmi") {
            let mut name = name.to_owned();
            name.replace_range(name.len() - 4.., GPP_SUFFIX);
            fs_path.push(&name);
            if let Ok(f) = fs::metadata(&fs_path).await {
                if f.is_file() {
                    return true;
                }
            }
            fs_path.pop();
        }

        false
    }

    /// returns (file path, args)
    async fn resolve_request<'a>(
        &self, vhost: &VhostCtx, path: &'a [String],
    ) -> io::Result<(PathBuf, &'a [String])> {
        for p in path.iter() {
            if p.starts_with('.') {
                return Err(Error::new(ErrorKind::InvalidInput, "hidden file"));
            }
        }

        let mut fs_path = vhost.root.clone();
        let mut i = 0;

        while i < path.len() {
            if path[i] == "" {
                i += 1;
                break;
            }
            fs_path.push(&path[i]);
            let f = fs::symlink_metadata(&fs_path).await;
            if f.is_err() || !f.unwrap().is_dir() {
                fs_path.pop();
                break;
            }
            i += 1;
        }

        if i < path.len() && self.test_file(&mut fs_path, &path[i]).await {
            i += 1;
            return Ok((fs_path, &path[i..]));
        } else if i != path.len() {
            return Err(Error::new(ErrorKind::NotFound, "not found"));
        } else if self.test_file(&mut fs_path, DEFAULT_FILENAME).await {
            return Ok((fs_path, &[]));
        }

        Err(Error::new(ErrorKind::NotFound, "not found"))
    }

    async fn handle_verbatim(
        &self, stream: &mut TlsStream<TcpStream>, path: &PathBuf,
    ) -> io::Result<u64> {
        log::debug!("sending verbatim {}", path.display());
        let mut f = BufReader::new(File::open(path).await?);
        Ok(tokio::io::copy(&mut f, stream).await?)
    }

    async fn load_gpp_data(
        &self, path: &PathBuf,
    ) -> io::Result<HashMap<String, String>> {
        let mut path = path.clone();
        path.set_extension("data");

        let mut data = HashMap::new();
        let Ok(f) = File::open(&path).await else {
            return Ok(data);
        };
        let mut lines = BufReader::new(f).lines();
        while let Some(ln) = lines.next_line().await? {
            let ln = ln.splitn(2, " ").collect::<Vec<_>>();
            if ln.len() == 2 {
                data.insert(ln[0].to_string(), ln[1].to_string());
            }
        }

        log::debug!("load data: {:?} -> {:?}", path, data);
        Ok(data)
    }

    fn resolve_file_path(
        vhost: &VhostCtx, path: &PathBuf, file: &str,
    ) -> PathBuf {
        if file.starts_with("/") {
            let mut path = vhost.root.clone();
            path.push(&file[1..]);
            path
        } else {
            let mut path = path.clone();
            path.pop();
            path.push(file);
            path
        }
    }

    async fn get_size(vhost: &VhostCtx, path: &PathBuf, file: &str) -> String {
        let path = Self::resolve_file_path(vhost, path, file);
        let Ok(meta) = fs::metadata(&path).await else {
            return String::new();
        };

        let sz = meta.len();
        if sz < 1024 {
            format!(" [{} bytes]", sz)
        } else if sz < 1024 * 1024 {
            format!(" [{} KB]", sz / 1024)
        } else {
            format!(" [{:.1} MB]", sz as f32 / 1024.0 / 1024.0)
        }
    }

    async fn resolve_image(
        &self, vhost: &VhostCtx, path: &PathBuf, file: &str,
    ) -> io::Result<String> {
        let small = if let Some(m) = self.ext_re.captures(file) {
            let mut file = m[1].to_owned();
            file.push_str("-small");
            file.push('.');
            file.push_str(&m[2]);
            Some(file)
        } else {
            None
        };

        if let Some(small) = small {
            let p = Self::resolve_file_path(vhost, path, &small);
            if fs::metadata(&p).await.is_ok() {
                return Ok(small);
            }
        }
        Ok(file.to_owned())
    }

    /// send gemini text, applying the gemini preprocessor
    async fn handle_gpp(
        &self, vhost: &VhostCtx, stream: &mut TlsStream<TcpStream>,
        path: &PathBuf,
    ) -> io::Result<u64> {
        let data = self.load_gpp_data(&path).await?;

        log::debug!("sending gpp {}", path.display());
        let mut lines = BufReader::new(File::open(path).await?).lines();
        let mut sent = 0;

        while let Some(mut ln) = lines.next_line().await? {
            while let Some(m) = self.tag_re.find(&ln) {
                let key = &ln[m.range()];
                let key = &key[2..key.len() - 2];
                if let Some(val) = data.get(key) {
                    ln.replace_range(m.range(), val);
                }
            }
            if let Some(m) = self.img_re.captures(&ln) {
                let img = self.resolve_image(vhost, path, &m[1]).await?;
                let sz = Self::get_size(vhost, path, &img).await;
                ln = format!("=> {} {}{}", &img, &m[3], sz);
            }
            ln.push_str("\r\n");
            sent += ln.len();
            stream.write_all(ln.as_bytes()).await?;
        }
        Ok(sent.try_into().unwrap_or_default())
    }

    async fn handle_gmi(
        &self, vhost: &VhostCtx, stream: &mut TlsStream<TcpStream>,
        path: &PathBuf,
    ) -> io::Result<u64> {
        let Some(filename) = path.file_name() else {
            return Err(Error::new(ErrorKind::NotFound, "no filename?"));
        };
        let Some(filename) = filename.to_str() else {
            return Err(Error::new(ErrorKind::NotFound, "name invalid utf-8"));
        };
        if !filename.ends_with(GPP_SUFFIX) {
            self.handle_verbatim(stream, path).await
        } else {
            self.handle_gpp(vhost, stream, path).await
        }
    }

    async fn handle_request(
        &self, vhost: &VhostCtx, stream: &mut TlsStream<TcpStream>,
        peer: &SocketAddr, request: &str,
    ) -> io::Result<()> {
        log::debug!("request: {:?}", request);
        let path = self.parse_request(vhost, request)?;
        let (path, args) = self.resolve_request(vhost, &path).await?;
        log::debug!("resolved: path {:?}, args {:?}", path, args);

        let mime = mime_guess::from_path(&path)
            .first()
            .unwrap_or(mime::APPLICATION_OCTET_STREAM);
        log::debug!("mime type: {}", mime);

        stream
            .write_all(&format!("20 {}\r\n", mime).as_bytes())
            .await?;

        const GEMTEXT: &str = "text/gemini";
        let sent = if mime == GEMTEXT {
            self.handle_gmi(vhost, stream, &path).await?
        } else {
            self.handle_verbatim(stream, &path).await?
        };

        log::info!("{} - {} - 20 - {} - {} bytes", peer, request, mime, sent);
        Ok(())
    }

    async fn handle(
        &self, vhost: &VhostCtx, stream: &mut TlsStream<TcpStream>,
        peer: &SocketAddr,
    ) -> io::Result<()> {
        let request = timeout(TIMEOUT, self.read_request(stream)).await??;
        timeout(TIMEOUT, self.handle_request(vhost, stream, peer, &request))
            .await?
    }

    async fn accepted(&self, stream: TcpStream, peer: SocketAddr) {
        let res = match timeout(TIMEOUT, self.setup(stream)).await {
            Ok(x) => x,
            Err(e) => {
                log::error!("{} - timeout during setup: {:?}", peer, e);
                return;
            }
        };
        let (mut stream, vhost) = match res {
            Ok((stream, vhost)) => (stream, vhost),
            Err(e) => {
                log::error!("{} - error during setup: {:?}", peer, e);
                return;
            }
        };
        if let Err(e) = self.handle(vhost, &mut stream, &peer).await {
            let msg = match e.kind() {
                ErrorKind::UnexpectedEof => None,
                ErrorKind::InvalidInput => Some("59 Bad request\r\n"),
                ErrorKind::NotFound => Some("51 Not found\r\n"),
                ErrorKind::TimedOut => Some("59 Bad request; too slow\r\n"),
                _ => Some("50 Permanent failure\r\n"),
            };
            log::error!(
                "{} - {} - {}",
                peer,
                e,
                msg.and_then(|x| Some(&x[..x.len() - 2]))
                    .unwrap_or_default()
            );
            if let Some(msg) = msg {
                let _ = stream.write_all(msg.as_bytes()).await;
            }
        }
    }

    async fn limit(&self, stream: TcpStream, peer: SocketAddr) {
        let ipaddr = match peer {
            SocketAddr::V4(_) => unimplemented!(),
            SocketAddr::V6(addr) => addr.ip().clone(),
        };
        self.ip_limit
            .throttle(ipaddr, move || {
                self.global_limit
                    .throttle((), move || self.accepted(stream, peer))
            })
            .await;
    }
}

pub async fn main(
    port: u16, root: String, setuid: Option<String>, chroot: bool,
) -> io::Result<()> {
    pretty_env_logger::formatted_timed_builder()
        .default_format()
        .filter_level(log::LevelFilter::Debug)
        .format_indent(None)
        .format_timestamp_micros()
        .init();

    let mut ctx = NsCtx::new(port);
    ctx.init_walk(&root)?;
    let ctx = Arc::new(ctx);

    let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port);
    let listener = TcpListener::bind(addr).await.unwrap();
    log::info!("bound to {}", addr);

    let mut uid = None;
    if let Some(ref username) = setuid {
        let Some(user) = users::get_user_by_name(username) else {
            return Err(Error::new(ErrorKind::NotFound, "unknown user"));
        };
        uid = Some(user.uid());
    }

    const CONTENT_DIR: &str = "content";
    let mut content = PathBuf::from(&root);
    content.push(CONTENT_DIR);

    if chroot {
        std::os::unix::fs::chroot(&content)?;
        std::env::set_current_dir("/")?;
        log::info!("chrooted to {}", content.display());
    } else {
        std::env::set_current_dir(&content)?;
    }

    if let Some(uid) = uid {
        unsafe {
            if libc::setuid(uid) != 0 {
                return Err(Error::new(ErrorKind::NotFound, "setuid failed"));
            }
        }
    }

    log::info!("ready");

    loop {
        let (stream, peer) = listener.accept().await.unwrap();
        let ctx = ctx.clone();
        tokio::spawn(async move {
            ctx.clone().limit(stream, peer).await;
        });
    }
}