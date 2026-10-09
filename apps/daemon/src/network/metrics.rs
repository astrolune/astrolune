// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Optional bounded loopback Prometheus endpoint with a joined shutdown path.

use std::{
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};
use telemetry::NodeMetrics;

pub(super) struct MetricsServer {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}
impl MetricsServer {
    pub(super) fn start(address: SocketAddr, metrics: Arc<NodeMetrics>) -> io::Result<Self> {
        if !address.ip().is_loopback() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let listener = TcpListener::bind(address)?;
        listener.set_nonblocking(true)?;
        println!("metrics   : http://{}/metrics", listener.local_addr()?);
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let thread = std::thread::Builder::new()
            .name("metrics".into())
            .spawn(move || {
                while !stopping.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            let _ = serve(stream, &metrics);
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(20));
                        }
                        Err(_) => break,
                    }
                }
            })?;
        Ok(Self {
            stop,
            thread: Some(thread),
        })
    }
}
impl Drop for MetricsServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
fn serve(mut stream: TcpStream, metrics: &NodeMetrics) -> io::Result<()> {
    // Windows accepts can inherit a nonblocking listener's mode, which the request
    // and response deadlines below do not clear. This socket's I/O is blocking.
    stream.set_nonblocking(false)?;
    let deadline = Instant::now() + Duration::from_millis(500);
    let mut request = Vec::new();
    while !request.ends_with(b"\r\n\r\n") {
        if request.len() >= 2048 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|time| !time.is_zero())
            .ok_or(io::ErrorKind::TimedOut)?;
        stream.set_read_timeout(Some(remaining))?;
        let mut byte = [0];
        stream.read_exact(&mut byte)?;
        request.push(byte[0]);
    }
    let valid = request.starts_with(b"GET /metrics HTTP/1.1\r\n")
        || request.starts_with(b"GET /metrics HTTP/1.0\r\n");
    let (status, body) = if valid {
        ("200 OK", metrics.prometheus())
    } else {
        ("404 Not Found", "not found\n".into())
    };
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let deadline = Instant::now() + Duration::from_millis(500);
    let mut remaining = response.as_bytes();
    while !remaining.is_empty() {
        let timeout = deadline
            .checked_duration_since(Instant::now())
            .filter(|time| !time.is_zero())
            .ok_or(io::ErrorKind::TimedOut)?;
        stream.set_write_timeout(Some(timeout))?;
        let count = stream.write(remaining)?;
        if count == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        remaining = &remaining[count..];
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn http_is_read_only_bounded_and_has_an_absolute_header_deadline() {
        for request in [
            b"GET /metrics HTTP/1.1\r\nHost: local\r\n\r\n".as_slice(),
            b"POST /metrics HTTP/1.1\r\n\r\n",
            b"GET /other HTTP/1.1\r\n\r\n",
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let server = std::thread::spawn(move || {
                serve(listener.accept().unwrap().0, &NodeMetrics::new(42, false))
            });
            client.write_all(request).unwrap();
            let mut response = String::new();
            client.read_to_string(&mut response).unwrap();
            assert!(response.contains(if request.starts_with(b"GET /metrics ") {
                "200 OK"
            } else {
                "404 Not Found"
            }));
            server.join().unwrap().unwrap();
        }
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let started = Instant::now();
        let server = std::thread::spawn(move || {
            serve(listener.accept().unwrap().0, &NodeMetrics::new(0, false))
        });
        for _ in 0..12 {
            if client.write_all(b"x").is_err() {
                break;
            }
            std::thread::sleep(Duration::from_millis(60));
        }
        assert!(server.join().unwrap().is_err());
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}
