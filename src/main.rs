//! Corvid entry point: init tracing, then run the mail service (SMTP + submission + relay +
//! webmail). Also exposes a dependency-free `corvid healthcheck` subcommand used as the
//! container HEALTHCHECK: it GETs `http://127.0.0.1:$PORT/healthz` (port from `WEBMAIL_ADDR`)
//! over a raw TCP socket and exits 0 on `200`, 1 otherwise — so the image needs no curl.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

#[tokio::main]
async fn main() {
    let arg1 = std::env::args().nth(1);
    match arg1.as_deref() {
        Some("healthcheck") => std::process::exit(run_healthcheck()),
        // `corvid dkim-verify <txt-path>`: read an RFC822 message on stdin and verify its
        // DKIM-Signature against the public key params in an OpenDKIM `default.txt`. Exit 0 when
        // the signature is valid. Used by the alt-port smoke for deterministic verification.
        Some("dkim-verify") => std::process::exit(run_dkim_verify(std::env::args().nth(2))),
        _ => {}
    }

    tracing_subscriber::fmt::init();

    if let Err(e) = corvid::run().await {
        tracing::error!(error = %e, "corvid failed to start");
        std::process::exit(1);
    }
}

/// GET `/healthz` over a raw TCP socket. Returns a process exit code (0 = healthy).
fn run_healthcheck() -> i32 {
    let bind = std::env::var("WEBMAIL_ADDR").unwrap_or_else(|_| "127.0.0.1:8800".to_string());
    let port = bind.rsplit(':').next().unwrap_or("8800");
    let target = format!("127.0.0.1:{port}");
    match healthcheck_once(&target) {
        Ok(true) => 0,
        Ok(false) => {
            eprintln!("healthcheck: {target} did not return 200");
            1
        }
        Err(e) => {
            eprintln!("healthcheck: {target} error: {e}");
            1
        }
    }
}

/// Read a message from stdin, verify its DKIM-Signature against the `p=` in `txt_path`.
fn run_dkim_verify(txt_path: Option<String>) -> i32 {
    let Some(txt_path) = txt_path else {
        eprintln!("usage: corvid dkim-verify <default.txt> < message");
        return 2;
    };
    let mut raw = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut raw) {
        eprintln!("dkim-verify: read stdin: {e}");
        return 2;
    }
    let txt = match std::fs::read_to_string(&txt_path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("dkim-verify: read {txt_path}: {e}");
            return 2;
        }
    };
    let Some(p) = corvid::dkim::extract_p_from_txt(&txt) else {
        eprintln!("dkim-verify: no p= in {txt_path}");
        return 2;
    };
    let der = match corvid::dkim::public_key_der_from_p(&p) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("dkim-verify: decode public key: {e}");
            return 2;
        }
    };
    match corvid::dkim::verify(&raw, &der) {
        Ok(true) => {
            println!("DKIM VALID");
            0
        }
        Ok(false) => {
            println!("DKIM INVALID");
            1
        }
        Err(e) => {
            eprintln!("dkim-verify: {e}");
            2
        }
    }
}

fn healthcheck_once(target: &str) -> std::io::Result<bool> {
    let addr: SocketAddr = target
        .parse()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("{e}")))?;
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2))?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    stream.write_all(b"GET /healthz HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
    let mut buf = String::new();
    stream.read_to_string(&mut buf)?;
    Ok(buf.lines().next().unwrap_or("").contains("200"))
}
