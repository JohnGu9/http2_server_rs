mod tls;

use std::{convert::Infallible, error::Error, net::SocketAddr, sync::Arc};

use bytes::Bytes;
use futures::channel::mpsc;
use futures::{Future, SinkExt};
use http_body_util::StreamBody;
use hyper::body::{Frame, Incoming};
use hyper::header::{self, HeaderValue};
use hyper::upgrade::Upgraded;
use hyper::{
    rt::Executor,
    server::conn::{http1, http2},
    service::service_fn,
    Request,
};
use hyper::{Method, Response, StatusCode, Version};
use hyper_util::rt::TokioIo;
use tls::{load_certs, load_keys};
use tokio::net::TcpStream;
use tokio_rustls::{rustls::ServerConfig, TlsAcceptor};
use tokio_tungstenite::{tungstenite, WebSocketStream};

pub type ResponseUnit = Result<Frame<Bytes>, Box<dyn std::error::Error + Send + Sync>>;
pub type ResponseType = Response<StreamBody<mpsc::Receiver<ResponseUnit>>>;

#[tokio::main]
async fn main() {
    let listener = tokio::net::TcpListener::bind("localhost:7200")
        .await
        .unwrap();

    let certs = load_certs().expect("No available ssl cert");
    let mut keys = load_keys().expect("No available ssl key");

    let mut config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, keys.pop().expect("No available ssl key"))
        .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"http/1.0".to_vec()];
    let config = Arc::new(config);
    let acceptor = TlsAcceptor::from(config.clone());

    println!("listen on https://{:?}", listener.local_addr().unwrap());

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                tokio::spawn(handle_connection(stream, addr, acceptor.clone()));
            }
            Err(e) => println!("Error: {:?}", e),
        }
    }
}

async fn handle_connection(stream: TcpStream, addr: SocketAddr, acceptor: TlsAcceptor) {
    match acceptor.accept(stream).await {
        Ok(stream) => {
            let (_, session) = stream.get_ref();
            let is_h2 = match session.alpn_protocol() {
                Some(alpn) => alpn == b"h2",
                None => false,
            };
            let stream = TokioIo::new(stream);
            let res = if is_h2 {
                println!("h2 from {}", addr);
                http2::Builder::new(TokioExecutor)
                    .serve_connection(stream, service_fn(on_http))
                    .await
            } else {
                println!("h1 from {}", addr);
                let handle = |req| http_websocket_classify(addr, req);
                http1::Builder::new()
                    .serve_connection(stream, service_fn(handle))
                    .with_upgrades()
                    .await
            };
            if let Err(e) = res {
                println!("Error: {:?}", e);
            }
        }
        Err(e) => {
            println!("SSL handshake error: {:?}", e);
        }
    }
}

#[derive(Clone)]
struct TokioExecutor;

impl<F> Executor<F> for TokioExecutor
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    fn execute(&self, future: F) {
        tokio::spawn(future);
    }
}

async fn http_websocket_classify(
    addr: SocketAddr,
    req: Request<Incoming>,
) -> Result<ResponseType, Infallible> {
    const UPGRADE_HEADER_VALUE: HeaderValue = HeaderValue::from_static("Upgrade");
    const WEBSOCKET_HEADER_VALUE: HeaderValue = HeaderValue::from_static("websocket");
    let headers = req.headers();
    let key = headers.get(header::SEC_WEBSOCKET_KEY);
    if let Some(key) = key {
        let derived = tungstenite::handshake::derive_accept_key(key.as_bytes()).parse();
        match derived {
            Ok(derived) => {
                if req.method() == Method::GET
                    && req.version() >= Version::HTTP_11
                    && headers
                        .get(header::CONNECTION)
                        .and_then(|h| h.to_str().ok())
                        .map(|h| {
                            h.split(|c| c == ' ' || c == ',')
                                .any(|p| p.eq_ignore_ascii_case("Upgrade"))
                        })
                        .unwrap_or(false)
                    && headers
                        .get(header::UPGRADE)
                        .and_then(|h| h.to_str().ok())
                        .map(|h| h.eq_ignore_ascii_case("websocket"))
                        .unwrap_or(false)
                    && headers
                        .get(header::SEC_WEBSOCKET_VERSION)
                        .map(|h| h == "13")
                        .unwrap_or(false)
                {
                    let (_, rx) = mpsc::channel(1);
                    let mut res = Response::new(StreamBody::new(rx));
                    *res.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
                    *res.version_mut() = req.version();
                    let headers = res.headers_mut();
                    headers.append(header::CONNECTION, UPGRADE_HEADER_VALUE);
                    headers.append(header::UPGRADE, WEBSOCKET_HEADER_VALUE);
                    headers.append(header::SEC_WEBSOCKET_ACCEPT, derived);
                    tokio::spawn(upgrade_web_socket(addr, req));
                    return Ok(res);
                } else {
                    println!( "Connection ({}) come with SEC_WEBSOCKET_KEY but can't upgrade to websocket and fallback to normal http handle. ",&addr);
                }
            }
            Err(err) => {
                println!("Error derive_accept_key: {}. ", err);
            }
        }
    }
    return on_http(req).await;
}

async fn upgrade_web_socket(addr: SocketAddr, mut req: Request<Incoming>) {
    match hyper::upgrade::on(&mut req).await {
        Ok(upgraded) => {
            let upgraded = TokioIo::new(upgraded);
            let ws_stream = WebSocketStream::from_raw_socket(
                upgraded,
                tungstenite::protocol::Role::Server,
                None,
            )
            .await;
            println!("Websocket({}) connected", addr);
            if let Err(err) = on_websocket(req, ws_stream).await {
                println!("Websocket({}) error({:?})", addr, err);
            }
            println!("Websocket({}) disconnected", addr);
        }
        Err(e) => {
            println!("Websocket upgrade error: {}", e);
        }
    }
}

async fn on_websocket(
    _: Request<Incoming>,
    _: WebSocketStream<TokioIo<Upgraded>>,
) -> Result<(), Box<dyn Error>> {
    /* websocket handle */
    Ok(())
}

async fn on_http(_: Request<Incoming>) -> Result<ResponseType, Infallible> {
    /* http handle */
    let (mut tx, rx) = mpsc::channel(0);
    tokio::spawn(async move {
        let _ = tx
            .send(Ok(Frame::data(Bytes::from("Hello".as_bytes()))))
            .await;
    });
    Ok(Response::new(StreamBody::new(rx)))
}
