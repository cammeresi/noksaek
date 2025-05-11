#[cfg(test)]
mod test;

#[cfg(fuzzing)]
pub mod fuzz;

use std::collections::HashMap;
use std::fmt::Debug;
use std::io::{self, Error};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use handlebars::Handlebars;
use regex::Regex;
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, PrivateSec1KeyDer},
    server::ServerConfig,
};
use rustls_pemfile::{certs, ec_private_keys};
use tokio::fs::{self, File};
use tokio::io::{
    AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt,
    BufReader, ErrorKind, ReadBuf, split,
};
use tokio::net::TcpListener;
use tokio::time::timeout;
use tokio_rustls::LazyConfigAcceptor;
use tokio_rustls::server::TlsStream;
use url::Url;

use crate::app::*;
use crate::*;
use linker_set::*;

pub const DEFAULT_PORT: u16 = 1965;
const DEFAULT_FILENAME: &str = "index.gmi";
const GPP_SUFFIX: &str = ".master.gmi";
const GPP_KEY_ERROR: &str = "[KEY ERROR]";
const BAN_SUFFIXES: &[&str] = &[GPP_SUFFIX, ".master.data"];

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
const IP_RATE_LIMIT: Duration = Duration::from_millis(100); // 10 per sec
const GLOBAL_RATE_LIMIT: Duration = Duration::from_millis(10); // 100 per sec

const ERR_BAD_REQUEST: &str = "59 Bad request";
const ERR_NOT_FOUND: &str = "51 Not found";
const ERR_TIMED_OUT: &str = "59 Bad request; too slow";

pub trait Vhost {
    fn name(&self) -> &str;
    fn root(&self) -> &PathBuf;
    fn get_cert(
        &self,
    ) -> (Vec<CertificateDer<'static>>, PrivateSec1KeyDer<'static>);
}

pub struct VhostCtx {
    name: String,
    certs: Vec<CertificateDer<'static>>,
    key: PrivateSec1KeyDer<'static>,
    rootdir: PathBuf,
}

impl Vhost for VhostCtx {
    fn name(&self) -> &str {
        &self.name
    }

    fn root(&self) -> &PathBuf {
        &self.rootdir
    }

    fn get_cert(
        &self,
    ) -> (Vec<CertificateDer<'static>>, PrivateSec1KeyDer<'static>) {
        (self.certs.clone(), self.key.clone_key())
    }
}

pub struct NsCtx<V> {
    port: u16,
    vhosts: HashMap<String, V>,
    timeout: Duration,
    tag_re: Regex,
    img_re: Regex,
    ext_re: Regex,
    ip_limit: MultiTokenBucket<Ipv6Addr>,
    global_limit: TokenBucket,
    apps: HashMap<String, Box<dyn Application + Send + Sync>>,
    tmpl: Handlebars<'static>,
}

impl<V> Debug for NsCtx<V> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "NsCtx")
    }
}

impl<V> NsCtx<V>
where
    V: Vhost,
{
    fn new(port: u16, timeout: Duration) -> Self {
        let mut s = Self {
            port,
            vhosts: HashMap::new(),
            timeout,
            tag_re: Regex::new(r"\[\[([^\[\]]+)\]\]").unwrap(),
            img_re: Regex::new(r"^=> ([^: ]+\.(gif|jpg|png|asc|pdf)) (.*)$")
                .unwrap(),
            ext_re: Regex::new(r"^(.*)\.([^\.]+)$").unwrap(),
            ip_limit: MultiTokenBucket::new(IP_RATE_LIMIT, 1),
            global_limit: TokenBucket::new(GLOBAL_RATE_LIMIT, 1),
            apps: HashMap::new(),
            tmpl: Handlebars::new(),
        };
        s.register_apps();
        s
    }

    fn register_apps(&mut self) {
        for app in set!(apps) {
            let (name, mut app) = app().expect("app creation failure");
            app.init(&mut self.tmpl)
                .unwrap_or_else(|_| panic!("app \"{name}\" init failed"));
            log::info!("registered app \"{name}\"");
            self.apps.insert(name, app);
        }
    }

    async fn setup<S>(&self, stream: S) -> io::Result<(TlsStream<S>, &V)>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
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

    pub async fn read_request<R>(stream: &mut R) -> io::Result<String>
    where
        R: AsyncReadExt + Unpin,
    {
        const MAX_REQUEST: usize = 1024 + 2; // 1 KB + crlf

        let mut buf = Vec::with_capacity(MAX_REQUEST);
        let mut rb = ReadBuf::uninit(buf.spare_capacity_mut());
        let mut read = 0;
        while rb.remaining() > 0 {
            let n = stream.read_buf(&mut rb).await?;
            read += n;
            if n == 0 || read >= 2 && rb.filled()[read - 2..read] == [13, 10] {
                break;
            }
        }
        unsafe {
            buf.set_len(read);
        }

        if read < 2 {
            return Err(Error::new(ErrorKind::InvalidInput, "no request"));
        } else if buf[read - 2..read] != [13, 10] {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "request too long",
            ));
        }

        buf.truncate(read - 2);
        match String::from_utf8(buf) {
            Ok(s) => Ok(s),
            Err(_) => Err(Error::new(ErrorKind::InvalidInput, "invalid utf8")),
        }
    }

    fn parse_request(
        &self, vhost: &V, request: &str,
    ) -> Result<Vec<String>, NokError> {
        let Ok(url) = Url::parse(request) else {
            return Err(
                Error::new(ErrorKind::InvalidInput, "invalid url").into()
            );
        };
        if url.scheme() != "gemini" {
            return Err(
                Error::new(ErrorKind::InvalidInput, "url scheme").into()
            );
        }
        if let Some(host) = url.host_str() {
            if host != vhost.name() {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "wrong hostname",
                )
                .into());
            }
        }
        let port = url.port().unwrap_or(DEFAULT_PORT);
        if port != self.port {
            return Err(
                Error::new(ErrorKind::InvalidInput, "wrong port").into()
            );
        }
        let segs = match url.path_segments() {
            None => Ok(Vec::new()),
            Some(path) => {
                path.map(urlencoding::decode).collect::<Result<Vec<_>, _>>()
            }
        };
        match segs {
            Err(_) => {
                Err(Error::new(ErrorKind::InvalidInput, "decode failure")
                    .into())
            }
            Ok(segs) => Ok(segs.iter().map(|x| x.to_string()).collect()),
        }
    }

    async fn test_application(
        &self, fs_path: &mut PathBuf, name: &str,
    ) -> bool {
        fs_path.push(format!("{name}.app"));
        if let Ok(f) = fs::metadata(&fs_path).await {
            if f.is_file() {
                return true;
            }
        }
        fs_path.pop();
        false
    }

    fn test_ban(name: &str) -> bool {
        for ban in BAN_SUFFIXES {
            if name.ends_with(ban) {
                return false;
            }
        }
        true
    }

    async fn test_gmi_file(&self, fs_path: &mut PathBuf, name: &str) -> bool {
        if !Self::test_ban(name) {
            return false;
        }

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

    fn redir_path(path: &[String]) -> String {
        let mut redir = String::from("/");
        for p in path {
            redir.push_str(p);
            redir.push('/');
        }
        redir
    }

    /// returns (file path, args)
    async fn resolve_request<'b>(
        &self, vhost: &V, path: &'b [String],
    ) -> Result<(PathBuf, &'b [String]), NokError> {
        for p in path.iter() {
            if p.starts_with('.') {
                return Err(
                    Error::new(ErrorKind::InvalidInput, "hidden file").into()
                );
            }
        }

        let mut fs_path = vhost.root().clone();
        let mut i = 0;
        let mut dir = false;

        while i < path.len() {
            if path[i].is_empty() {
                i += 1;
                dir = true;
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

        if i < path.len() && self.test_application(&mut fs_path, &path[i]).await
        {
            // application
            Ok((fs_path, &path[i + 1..]))
        } else if i == path.len() - 1
            && self.test_gmi_file(&mut fs_path, &path[i]).await
        {
            // file
            Ok((fs_path, &[]))
        } else if i != path.len() {
            // further arguments are not allowed
            Err(Error::new(ErrorKind::NotFound, "not found").into())
        } else if self.test_gmi_file(&mut fs_path, DEFAULT_FILENAME).await {
            // default
            if dir {
                Ok((fs_path, &[]))
            } else {
                Err(NokError::Redirect(Self::redir_path(path)))
            }
        } else {
            Err(Error::new(ErrorKind::NotFound, "not found").into())
        }
    }

    async fn handle_verbatim<W>(
        &self, stream: &mut W, path: &PathBuf,
    ) -> io::Result<u64>
    where
        W: AsyncWrite + Send + Unpin,
    {
        log::debug!("sending verbatim {}", path.display());
        let mut f = BufReader::new(File::open(path).await?);
        tokio::io::copy(&mut f, stream).await
    }

    async fn load_gpp_data(
        &self, path: &Path,
    ) -> io::Result<HashMap<String, String>> {
        let mut path = path.to_path_buf();
        path.set_extension("data");

        let mut data = HashMap::new();
        let Ok(f) = File::open(&path).await else {
            return Ok(data);
        };
        let mut lines = BufReader::new(f).lines();
        while let Some(ln) = lines.next_line().await? {
            let ln = ln.splitn(2, ' ').collect::<Vec<_>>();
            if ln.len() == 2 {
                data.insert(ln[0].into(), ln[1].into());
            }
        }

        log::debug!("load data: {path:?} -> {data:?}");
        Ok(data)
    }

    fn resolve_file_path(vhost: &V, path: &Path, file: &str) -> PathBuf {
        if let Some(stripped) = file.strip_prefix('/') {
            let mut path = vhost.root().clone();
            path.push(stripped);
            path
        } else {
            let mut path = path.to_path_buf();
            path.pop();
            path.push(file);
            path
        }
    }

    async fn get_size(vhost: &V, path: &Path, file: &str) -> String {
        let path = Self::resolve_file_path(vhost, path, file);
        let Ok(meta) = fs::metadata(&path).await else {
            return String::new();
        };

        let sz = meta.len();
        if sz < 1024 {
            format!(" [{sz} bytes]")
        } else if sz < 1024 * 1024 {
            format!(" [{} KB]", sz / 1024)
        } else if sz < 10 * 1024 * 1024 {
            format!(" [{:.1} MB]", sz as f32 / 1024.0 / 1024.0)
        } else {
            format!(" [{} MB]", sz / 1024 / 1024)
        }
    }

    async fn resolve_image(
        &self, vhost: &V, path: &Path, file: &str,
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
    async fn handle_gpp<W>(
        &self, vhost: &V, stream: &mut W, path: &PathBuf,
    ) -> io::Result<u64>
    where
        W: AsyncWrite + Send + Unpin,
    {
        let data = self.load_gpp_data(path).await?;

        log::debug!("sending gpp {}", path.display());
        let mut lines = BufReader::new(File::open(path).await?).lines();
        let mut sent = 0;

        while let Some(mut ln) = lines.next_line().await? {
            while let Some(m) = self.tag_re.find(&ln) {
                let key = &ln[m.range()];
                let key = &key[2..key.len() - 2];
                if let Some(val) = data.get(key) {
                    ln.replace_range(m.range(), val);
                } else {
                    ln.replace_range(m.range(), GPP_KEY_ERROR);
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

    async fn handle_gmi<W>(
        &self, vhost: &V, stream: &mut W, path: &PathBuf,
    ) -> io::Result<u64>
    where
        W: AsyncWrite + Send + Unpin,
    {
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

    async fn handle_app<W>(
        &self, _vhost: &V, stream: &mut W, peer: &SocketAddr, path: &PathBuf,
        args: &[String],
    ) -> io::Result<u64>
    where
        W: AsyncWrite + Send + Unpin,
    {
        let app = fs::read_to_string(&path).await?;
        let app = app.trim();
        log::info!("running app {app} {args:?}");
        let Some(app) = self.apps.get(app) else {
            return Err(Error::new(
                ErrorKind::NotFound,
                format!("unregistered app \"{app}\""),
            ));
        };
        let stream = Box::new(stream as &mut (dyn AsyncWrite + Send + Unpin));
        app.run(args, stream, peer, &self.tmpl).await
    }

    /// returns (byte sent, mime type)
    async fn handle_request<W>(
        &self, vhost: &V, stream: &mut W, peer: &SocketAddr, path: &[String],
    ) -> Result<(u64, String), NokError>
    where
        W: AsyncWrite + Send + Unpin,
    {
        let (path, args) = self.resolve_request(vhost, path).await?;
        log::debug!("resolved: path {path:?}, args {args:?}");

        let mime = mime_guess::from_path(&path)
            .first()
            .unwrap_or(mime::APPLICATION_OCTET_STREAM);
        let mut mime = mime.as_ref();

        const GEMTEXT: &str = "text/gemini";
        let mut app = false;
        if let Some(ext) = path.extension() {
            if ext.as_encoded_bytes() == "app".as_bytes() {
                app = true;
                mime = GEMTEXT;
            }
        }

        log::debug!("mime type: {mime}");
        stream
            .write_all(format!("20 {mime}\r\n").as_bytes())
            .await?;

        let sent = if app {
            self.handle_app(vhost, stream, peer, &path, args).await?
        } else if mime == GEMTEXT {
            self.handle_gmi(vhost, stream, &path).await?
        } else {
            self.handle_verbatim(stream, &path).await?
        };

        Ok((sent, mime.into()))
    }

    fn flatten_result<T, E1, E2>(
        res: Result<Result<T, E1>, E2>,
    ) -> Result<T, NokError>
    where
        NokError: From<E1> + From<E2>,
    {
        match res {
            Err(e) => Err(e.into()),
            Ok(Err(e)) => Err(e.into()),
            Ok(Ok(x)) => Ok(x),
        }
    }

    async fn handle<R, W>(
        &self, vhost: &V, r: &mut R, w: &mut W, peer: &SocketAddr,
    ) where
        R: AsyncReadExt + Send + Unpin,
        W: AsyncWrite + Send + Unpin,
    {
        let (mut request, mut mime, mut sent) = (None, None, None);

        #[allow(clippy::never_loop)]
        let err = loop {
            let res = timeout(self.timeout, Self::read_request(r)).await;
            let res = Self::flatten_result(res);
            break_error!(res);

            request = Some(res.unwrap());
            log::debug!("request: {request:?}");
            let res = self.parse_request(vhost, request.as_ref().unwrap());
            break_error!(res);

            let path = res.unwrap();
            let res = timeout(
                self.timeout,
                self.handle_request(vhost, w, peer, &path),
            )
            .await;
            let res = Self::flatten_result(res);
            break_error!(res);

            let (s, m) = res.unwrap();
            (sent, mime) = (Some(s), Some(m));
            break None;
        };

        let msg = if let Some(e) = err {
            if let Some(msg) = Self::error_message(&e) {
                let _ = w.write_all(msg.as_bytes()).await;
                let _ = w.write_all(b"\r\n").await;
                msg
            } else {
                "".into()
            }
        } else {
            "20".into()
        };

        if request.is_none() {
            log::info!("{peer} - [no request] - {msg}");
        } else if mime.is_none() || sent.is_none() {
            let request = request.unwrap();
            log::info!("{peer} - {request} - {msg}");
        } else {
            let request = request.unwrap();
            let mime = mime.unwrap();
            let sent = sent.unwrap();
            log::info!("{peer} - {request} - {msg} - {mime} - {sent} bytes");
        }
    }

    fn error_message(e: &NokError) -> Option<String> {
        match e {
            NokError::IoError(e) => match e.kind() {
                ErrorKind::UnexpectedEof => None,
                ErrorKind::InvalidInput => Some(ERR_BAD_REQUEST.into()),
                ErrorKind::NotFound => Some(ERR_NOT_FOUND.into()),
                ErrorKind::TimedOut => Some(ERR_TIMED_OUT.into()),
                _ => Some("50 Permanent failure".into()),
            },
            NokError::Redirect(url) => Some(format!("31 {url}")),
        }
    }

    async fn accepted<S>(&self, stream: S, peer: SocketAddr)
    where
        S: AsyncRead + AsyncWrite + Send + Unpin,
    {
        let res = match timeout(self.timeout, self.setup(stream)).await {
            Ok(x) => x,
            Err(e) => {
                log::warn!("{peer} - timeout during setup: {e:?}");
                return;
            }
        };
        let (stream, vhost) = match res {
            Ok((stream, vhost)) => (stream, vhost),
            Err(e) => {
                log::warn!("{peer} - failed during setup: {e:?}");
                return;
            }
        };
        let (mut r, mut w) = split(stream);
        self.handle(vhost, &mut r, &mut w, &peer).await
    }

    async fn limit<S>(&self, stream: S, peer: SocketAddr)
    where
        S: AsyncRead + AsyncWrite + Send + Unpin,
    {
        let ipaddr = match peer {
            SocketAddr::V4(_) => unimplemented!(),
            SocketAddr::V6(addr) => *addr.ip(),
        };
        self.ip_limit.acquire(ipaddr).await;
        self.global_limit.acquire().await;
        self.accepted(stream, peer).await;
    }

    fn add_host(&mut self, host: String, vhost: V) {
        self.vhosts.insert(host, vhost);
    }

    #[cfg(test)]
    fn get_host(&self, name: &str) -> &V {
        self.vhosts.get(name).expect("unknown vhost")
    }
}

fn read_file(p: PathBuf) -> io::Result<io::BufReader<std::fs::File>> {
    Ok(io::BufReader::new(std::fs::File::open(p)?))
}

fn add_host(
    ctx: &mut NsCtx<VhostCtx>, host: String,
    certs: Vec<CertificateDer<'static>>, key: PrivateSec1KeyDer<'static>,
    root: PathBuf,
) {
    log::info!("adding vhost {host}");
    ctx.add_host(
        host.clone(),
        VhostCtx {
            name: host,
            certs,
            key,
            rootdir: root,
        },
    );
}

fn init_walk(ctx: &mut NsCtx<VhostCtx>, root: &str) -> io::Result<()> {
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
        let c = certs(&mut read_file(p)?)
            .map(|x| x.unwrap())
            .collect::<Vec<_>>();
        path[3] = KEY;
        let p = path.iter().collect::<PathBuf>();
        let k = ec_private_keys(&mut read_file(p)?)
            .next()
            .expect("no key")?;

        let content = [&host];
        add_host(ctx, host.clone(), c, k, content.iter().collect());
    }
    Ok(())
}

fn setup_logger(logdir: Option<String>) {
    use flexi_logger::{
        AdaptiveFormat, Cleanup, Criterion, FileSpec, Logger, Naming,
        opt_format,
    };

    let mut log = Logger::try_with_str("info").unwrap();
    if let Some(dir) = logdir {
        log = log.log_to_file(
            FileSpec::default().directory(dir).basename("noksaek"),
        );
    }
    log.rotate(
        Criterion::Size(100 * 1024 * 1024),
        Naming::Numbers,
        Cleanup::KeepLogFiles(10),
    )
    .adaptive_format_for_stderr(AdaptiveFormat::Opt)
    .format_for_files(opt_format)
    .start()
    .unwrap();
}

pub async fn main(
    port: u16, root: String, logdir: Option<String>, setuid: Option<String>,
    chroot: bool,
) -> io::Result<()> {
    setup_logger(logdir);

    let mut ctx = NsCtx::<VhostCtx>::new(port, DEFAULT_TIMEOUT);
    init_walk(&mut ctx, &root)?;
    let ctx = Arc::new(ctx);

    let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port);
    let listener = TcpListener::bind(addr).await.unwrap();
    log::info!("bound to {addr}");

    let mut uid = None;
    if let Some(ref username) = setuid {
        let Some(user) = uzers::get_user_by_name(username) else {
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
