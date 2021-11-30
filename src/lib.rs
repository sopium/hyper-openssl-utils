use foreign_types::ForeignTypeRef;
use futures_util::future::poll_fn;
use hyper::{
    body::{to_bytes, Bytes},
    header::HeaderValue,
    server::{accept::Accept, conn::AddrIncoming},
    Client, Request,
};
use libc::{c_uint, timegm, tm};
use openssl::{
    hash::MessageDigest,
    ocsp::{OcspCertId, OcspCertStatus, OcspRequest, OcspResponse, OcspResponseStatus},
    ssl::{Ssl, SslAcceptor},
    x509::X509,
};
use openssl_sys::{ASN1_GENERALIZEDTIME, ASN1_TIME};
use std::{
    fmt, io, mem,
    net::SocketAddr,
    pin::Pin,
    task::{self, Poll},
    time::{Duration, SystemTime},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    sync::{mpsc::Receiver, watch},
    task::JoinHandle,
    time::timeout,
};
use tokio_openssl::SslStream;

extern "C" {
    fn ASN1_TIME_to_tm(t: *const ASN1_TIME, tm: *mut tm) -> c_uint;
}

pub struct GetOcspResult {
    pub res: Bytes,
    pub expires: Duration,
    pub next_fetch: Duration,
}

#[derive(Debug)]
pub struct NoOcspResponderError;

impl fmt::Display for NoOcspResponderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "No OCSP Responder")
    }
}

impl std::error::Error for NoOcspResponderError {}

fn asn1_time_to_system_time(t: *mut ASN1_GENERALIZEDTIME) -> SystemTime {
    let mut tm = unsafe { mem::zeroed() };
    let t = unsafe {
        ASN1_TIME_to_tm(t as *mut ASN1_TIME, &mut tm);
        timegm(&mut tm)
    };
    if t > 0 {
        SystemTime::UNIX_EPOCH + Duration::from_secs(t as u64)
    } else {
        SystemTime::UNIX_EPOCH + Duration::from_secs((-t) as u64)
    }
}

#[test]
fn test_ansi1_time_to_system_time() {
    use openssl::asn1::Asn1Time;
    let t0 = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let t = Asn1Time::from_unix(t0 as i64).unwrap();
    let t1 = asn1_time_to_system_time(t.as_ptr() as *mut _ as *mut _);
    assert_eq!(t1, SystemTime::UNIX_EPOCH + Duration::from_secs(t0));
}

pub async fn get_ocsp_status(cert: &X509, issuer: &X509) -> anyhow::Result<GetOcspResult> {
    tracing::info!(cert = ?cert.subject_name(), "getting OCSP status");
    let responders = cert.ocsp_responders()?;
    let responder = responders.into_iter().next().ok_or(NoOcspResponderError)?;
    let mut req = OcspRequest::new()?;
    let cert_id = OcspCertId::from_cert(MessageDigest::sha1(), cert, issuer)?;
    req.add_id(cert_id)?;
    let req = req.to_der()?;
    let req = Request::post(&**responder)
        .header("content-type", "application/ocsp-request")
        .body(req.into())?;
    let client = Client::new();
    let res = client.request(req).await?;
    anyhow::ensure!(res.status().is_success());
    anyhow::ensure!(
        res.headers().get("content-type")
            == Some(&HeaderValue::from_static("application/ocsp-response"))
    );
    let mut max_age: Option<Duration> = None;
    if let Some(cache_control) = res.headers().get("cache-control") {
        let cache_control = cache_control.to_str()?;
        for v in cache_control.split_ascii_whitespace() {
            if let Some(m) = v.trim().strip_prefix("max-age=") {
                if let Ok(m) = m.parse() {
                    tracing::info!(max_age = m, "OCSP response HTTP cache-control");
                    max_age = Some(Duration::from_secs(m));
                    break;
                }
            }
        }
    }
    let res = to_bytes(res.into_body()).await?;
    let response = OcspResponse::from_der(&res)?;
    anyhow::ensure!(response.status() == OcspResponseStatus::SUCCESSFUL);
    let basic = response.basic()?;
    let cert_id = OcspCertId::from_cert(MessageDigest::sha1(), cert, issuer)?;
    let status = basic
        .find_status(&cert_id)
        .ok_or_else(|| anyhow::format_err!("find status"))?;
    anyhow::ensure!(status.status == OcspCertStatus::GOOD);
    let next_update = asn1_time_to_system_time(status.next_update.as_ptr());
    let next_update = next_update.duration_since(SystemTime::now())?;
    let next_fetch_calculated_by_next_update = if next_update > Duration::from_secs(24 * 60 * 60) {
        Duration::from_secs(24 * 60 * 60)
    } else {
        next_update.saturating_sub(Duration::from_secs(5))
    };
    let next_fetch = if let Some(max_age) = max_age {
        std::cmp::min(max_age, next_fetch_calculated_by_next_update)
    } else {
        next_fetch_calculated_by_next_update
    };
    tracing::info!(?next_update, ?next_fetch, len = res.len(), "OCSP response");
    Ok(GetOcspResult {
        res,
        next_fetch,
        expires: next_update,
    })
}

/// # Panics
///
/// If the certificate does not specify any OCSP responders.
async fn get_ocsp_status_retry(cert: &X509, issuer: &X509) -> GetOcspResult {
    let mut error_delay = Duration::from_secs(1);
    loop {
        match get_ocsp_status(cert, issuer).await {
            Ok(r) => return r,
            Err(e) if e.downcast_ref::<NoOcspResponderError>().is_some() => panic!("{}", e),
            Err(e) => {
                tracing::warn!(%e, "failed to get OCSP response");
                tokio::time::sleep(error_delay).await;
                error_delay *= 2;
                // TODO: make configurable.
                error_delay = std::cmp::min(error_delay, Duration::from_secs(60));
            }
        }
    }
}

pub fn spawn_get_ocsp(cert: &X509, issuer: &X509) -> watch::Receiver<Option<Bytes>> {
    let (tx, rx) = watch::channel(None);
    let no_responder = if let Ok(r) = cert.ocsp_responders() {
        r.is_empty()
    } else {
        false
    };
    if no_responder {
        return rx;
    }

    let cert = cert.clone();
    let issuer = issuer.clone();
    tokio::spawn(async move {
        let expired = tokio::time::sleep(Duration::MAX);
        tokio::pin!(expired);
        loop {
            tokio::select! {
                _ = &mut expired => {
                    if tx.send(None).is_err() {
                        break;
                    }
                    expired.as_mut().reset(tokio::time::Instant::now() + Duration::MAX);
                },
                result = get_ocsp_status_retry(&cert, &issuer) => {
                    if tx.send(Some(result.res)).is_err() {
                        break;
                    }
                    expired.as_mut().reset(tokio::time::Instant::now() + result.expires);
                    tokio::time::sleep(result.next_fetch).await;
                }
            }
        }
    });
    rx
}

pub struct TlsAddrIncoming {
    rx: Receiver<io::Result<TlsAddrStream>>,
    handle: JoinHandle<()>,
}

#[derive(Debug)]
pub struct TlsAddrStream {
    remote_addr: SocketAddr,
    stream: SslStream<TcpStream>,
}

impl fmt::Debug for TlsAddrIncoming {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsAddrIncoming").finish()
    }
}

impl Drop for TlsAddrIncoming {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

impl TlsAddrIncoming {
    pub fn new(
        mut addr_incoming: AddrIncoming,
        acceptor: SslAcceptor,
        handshake_timeout: Duration,
    ) -> Self {
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        let handle = tokio::spawn(async move {
            loop {
                match poll_fn(|cx| Pin::new(&mut addr_incoming).poll_accept(cx)).await {
                    Some(Ok(stream)) => {
                        let remote_addr = stream.remote_addr();
                        let stream = stream.into_inner();
                        let tx = tx.clone();
                        let acceptor = acceptor.clone();
                        tokio::spawn(async move {
                            if let Ok(ssl) = Ssl::new(acceptor.context()) {
                                if let Ok(mut stream) = SslStream::new(ssl, stream) {
                                    if matches!(
                                        timeout(handshake_timeout, Pin::new(&mut stream).accept())
                                            .await,
                                        Ok(Ok(_))
                                    ) {
                                        let _ = tx
                                            .send(Ok(TlsAddrStream {
                                                remote_addr,
                                                stream,
                                            }))
                                            .await;
                                    }
                                }
                            }
                        });
                    }
                    Some(Err(e)) => {
                        if tx.send(Err(e)).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
        });
        Self { rx, handle }
    }
}

impl Accept for TlsAddrIncoming {
    type Conn = TlsAddrStream;

    type Error = io::Error;

    fn poll_accept(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> Poll<Option<Result<Self::Conn, Self::Error>>> {
        self.rx.poll_recv(cx)
    }
}

impl TlsAddrStream {
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    pub fn into_inner(self) -> SslStream<TcpStream> {
        self.stream
    }
}

impl AsyncRead for TlsAddrStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for TlsAddrStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}
