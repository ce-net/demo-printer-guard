//! Just enough HTTP/1.1 over `std::net` for cells on one machine to call each other: a threaded
//! server whose handlers answer JSON or stream newline-delimited JSON, and a client that posts JSON
//! and reads the answer whole or line by line. Every connection carries one request.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

pub struct Req {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Req {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

/// Where a handler writes its answer.
pub struct Res {
    stream: TcpStream,
    started: bool,
}

impl Res {
    /// A whole JSON answer.
    pub fn send(&mut self, status: u16, v: &serde_json::Value) {
        let body = serde_json::to_vec(v).unwrap_or_default();
        let _ = write!(
            self.stream,
            "HTTP/1.1 {status} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            reason(status),
            body.len()
        );
        let _ = self.stream.write_all(&body);
        self.started = true;
    }

    /// Start a stream of JSON lines; then call [`Res::line`] for each.
    pub fn stream(&mut self, status: u16) {
        let _ = write!(self.stream, "HTTP/1.1 {status} {}\r\nContent-Type: application/x-ndjson\r\nConnection: close\r\n\r\n", reason(status));
        self.started = true;
    }

    pub fn line(&mut self, v: &serde_json::Value) {
        let mut b = serde_json::to_vec(v).unwrap_or_default();
        b.push(b'\n');
        let _ = self.stream.write_all(&b);
        let _ = self.stream.flush();
    }
}

fn reason(s: u16) -> &'static str {
    match s {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        502 => "Bad Gateway",
        _ => "Status",
    }
}

fn read_req(s: &TcpStream) -> std::io::Result<Req> {
    let mut r = BufReader::new(s.try_clone()?);
    let mut first = String::new();
    r.read_line(&mut first)?;
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("/").to_string();
    let mut headers = Vec::new();
    loop {
        let mut l = String::new();
        if r.read_line(&mut l)? == 0 {
            break;
        }
        let l = l.trim_end();
        if l.is_empty() {
            break;
        }
        if let Some((k, v)) = l.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    let len: usize = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("content-length")).and_then(|(_, v)| v.parse().ok()).unwrap_or(0);
    if len > 8 << 20 {
        return Err(std::io::Error::other("body too large"));
    }
    let mut body = vec![0; len];
    r.read_exact(&mut body)?;
    Ok(Req { method, path, headers, body })
}

/// Serve `handler` on `addr` (one thread per connection) until the process ends.
pub fn serve<F>(addr: &str, handler: F) -> std::io::Result<()>
where
    F: Fn(Req, &mut Res) + Send + Sync + 'static,
{
    let l = TcpListener::bind(addr)?;
    let h = Arc::new(handler);
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            let h = h.clone();
            std::thread::spawn(move || {
                let _ = s.set_read_timeout(Some(Duration::from_secs(30)));
                let Ok(req) = read_req(&s) else { return };
                let mut res = Res { stream: s, started: false };
                h(req, &mut res);
                if !res.started {
                    res.send(500, &serde_json::json!({"error": "no answer"}));
                }
            });
        }
    });
    Ok(())
}

fn split(url: &str) -> Result<(String, String), String> {
    let rest = url.strip_prefix("http://").ok_or_else(|| format!("{url}: only http:// is supported"))?;
    let (host, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    Ok((host.to_string(), path.to_string()))
}

fn send(url: &str, body: &[u8], headers: &[(&str, &str)]) -> Result<BufReader<TcpStream>, String> {
    let (host, path) = split(url)?;
    let mut s = TcpStream::connect(&host).map_err(|e| format!("{host}: {e}"))?;
    let _ = s.set_read_timeout(Some(Duration::from_secs(60)));
    let mut head = format!("POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n", body.len());
    for (k, v) in headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    s.write_all(head.as_bytes()).and_then(|_| s.write_all(body)).map_err(|e| format!("{host}: {e}"))?;
    Ok(BufReader::new(s))
}

fn status_line(r: &mut BufReader<TcpStream>) -> Result<u16, String> {
    let mut first = String::new();
    r.read_line(&mut first).map_err(|e| e.to_string())?;
    let status = first.split_whitespace().nth(1).and_then(|s| s.parse().ok()).ok_or_else(|| format!("bad status line `{}`", first.trim()))?;
    let mut chunked = false;
    loop {
        let mut l = String::new();
        if r.read_line(&mut l).map_err(|e| e.to_string())? == 0 {
            break;
        }
        let t = l.trim();
        if t.is_empty() {
            break;
        }
        if t.to_ascii_lowercase().starts_with("transfer-encoding:") && t.to_ascii_lowercase().contains("chunked") {
            chunked = true;
        }
    }
    if chunked {
        return Err("chunked answers are not supported".into());
    }
    Ok(status)
}

/// POST JSON, read the whole answer as JSON.
pub fn post(url: &str, body: &serde_json::Value, headers: &[(&str, &str)]) -> Result<(u16, serde_json::Value), String> {
    let mut r = send(url, &serde_json::to_vec(body).unwrap_or_default(), headers)?;
    let status = status_line(&mut r)?;
    let mut b = Vec::new();
    r.read_to_end(&mut b).map_err(|e| e.to_string())?;
    let v = serde_json::from_slice(&b).map_err(|e| format!("{url}: answer is not JSON: {e}"))?;
    Ok((status, v))
}

/// POST JSON, call `each` with every JSON line of the answer as it arrives.
pub fn post_lines(url: &str, body: &serde_json::Value, mut each: impl FnMut(serde_json::Value)) -> Result<u16, String> {
    let mut r = send(url, &serde_json::to_vec(body).unwrap_or_default(), &[])?;
    let status = status_line(&mut r)?;
    for l in r.lines() {
        let l = l.map_err(|e| e.to_string())?;
        if l.trim().is_empty() {
            continue;
        }
        each(serde_json::from_str(&l).map_err(|e| format!("{url}: line is not JSON: {e}"))?);
    }
    Ok(status)
}
