//! Minimal async DNS stub resolver (UDP) for the two lookups the mailer needs: MX (outbound
//! routing) and TXT (advisory SPF). Deliberately dependency-free — a tiny hand-rolled wire
//! codec over `tokio::net::UdpSocket` reading the first `nameserver` from `/etc/resolv.conf`
//! (falling back to public resolvers) — so the service pulls in no large DNS crate.
//!
//! It implements just enough of RFC 1035 message parsing (header + question echo + answer RRs,
//! with name-compression pointers) to read MX preference/exchange and TXT character-strings.

use std::net::Ipv4Addr;
use std::time::Duration;

use tokio::net::UdpSocket;

const TYPE_A: u16 = 1;
const TYPE_TXT: u16 = 16;
const TYPE_MX: u16 = 15;
const CLASS_IN: u16 = 1;

/// An MX record: lower `pref` is preferred.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MxRecord {
    pub pref: u16,
    pub exchange: String,
}

/// Resolve MX records for `domain`, sorted by ascending preference. Empty on NODATA/NXDOMAIN.
pub async fn resolve_mx(domain: &str) -> std::io::Result<Vec<MxRecord>> {
    let answers = query(domain, TYPE_MX).await?;
    let mut out: Vec<MxRecord> = answers
        .into_iter()
        .filter_map(|a| match a {
            Rdata::Mx { pref, exchange } => Some(MxRecord { pref, exchange }),
            _ => None,
        })
        .collect();
    out.sort_by(|a, b| a.pref.cmp(&b.pref).then_with(|| a.exchange.cmp(&b.exchange)));
    Ok(out)
}

/// Resolve TXT records for `domain` (each record's character-strings concatenated).
pub async fn resolve_txt(domain: &str) -> std::io::Result<Vec<String>> {
    let answers = query(domain, TYPE_TXT).await?;
    Ok(answers
        .into_iter()
        .filter_map(|a| match a {
            Rdata::Txt(s) => Some(s),
            _ => None,
        })
        .collect())
}

/// Resolve A records for `host`.
pub async fn resolve_a(host: &str) -> std::io::Result<Vec<Ipv4Addr>> {
    let answers = query(host, TYPE_A).await?;
    Ok(answers
        .into_iter()
        .filter_map(|a| match a {
            Rdata::A(ip) => Some(ip),
            _ => None,
        })
        .collect())
}

#[derive(Debug)]
enum Rdata {
    A(Ipv4Addr),
    Mx { pref: u16, exchange: String },
    Txt(String),
    Other,
}

/// Send one query and parse the answer section. 4s timeout; one retry on a second resolver.
async fn query(name: &str, qtype: u16) -> std::io::Result<Vec<Rdata>> {
    let servers = nameservers();
    let mut last_err: Option<std::io::Error> = None;
    for server in servers {
        match query_one(&server, name, qtype).await {
            Ok(v) => return Ok(v),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| std::io::Error::other("no nameserver available")))
}

async fn query_one(server: &str, name: &str, qtype: u16) -> std::io::Result<Vec<Rdata>> {
    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    sock.connect((server, 53)).await?;
    let id: u16 = rand::random();
    let packet = build_query(id, name, qtype);
    sock.send(&packet).await?;

    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(4), sock.recv(&mut buf))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "dns timeout"))??;
    buf.truncate(n);
    parse_answers(&buf, qtype)
}

/// First nameserver(s) from /etc/resolv.conf, plus public fallbacks.
fn nameservers() -> Vec<String> {
    let mut v: Vec<String> = Vec::new();
    if let Ok(content) = std::fs::read_to_string("/etc/resolv.conf") {
        for line in content.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("nameserver") {
                let ip = rest.trim();
                if !ip.is_empty() && !ip.contains(':') {
                    v.push(ip.to_string());
                }
            }
        }
    }
    v.push("1.1.1.1".to_string());
    v.push("8.8.8.8".to_string());
    v.dedup();
    v
}

fn build_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut p = Vec::with_capacity(32 + name.len());
    p.extend_from_slice(&id.to_be_bytes());
    p.extend_from_slice(&0x0100u16.to_be_bytes()); // RD set
    p.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    p.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    p.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    p.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    for label in name.trim_end_matches('.').split('.') {
        let bytes = label.as_bytes();
        p.push(bytes.len() as u8);
        p.extend_from_slice(bytes);
    }
    p.push(0); // root
    p.extend_from_slice(&qtype.to_be_bytes());
    p.extend_from_slice(&CLASS_IN.to_be_bytes());
    p
}

fn parse_answers(buf: &[u8], qtype: u16) -> std::io::Result<Vec<Rdata>> {
    if buf.len() < 12 {
        return Err(short());
    }
    let qd = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let an = u16::from_be_bytes([buf[6], buf[7]]) as usize;

    let mut pos = 12;
    // Skip the question section.
    for _ in 0..qd {
        pos = skip_name(buf, pos)?;
        pos += 4; // QTYPE + QCLASS
    }

    let mut out = Vec::new();
    for _ in 0..an {
        pos = skip_name(buf, pos)?;
        if pos + 10 > buf.len() {
            return Err(short());
        }
        let rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let rdlen = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > buf.len() {
            return Err(short());
        }
        let rdata = &buf[pos..pos + rdlen];
        if rtype == qtype {
            out.push(parse_rdata(buf, rtype, pos, rdlen, rdata)?);
        }
        pos += rdlen;
    }
    Ok(out)
}

fn parse_rdata(
    buf: &[u8],
    rtype: u16,
    pos: usize,
    rdlen: usize,
    rdata: &[u8],
) -> std::io::Result<Rdata> {
    match rtype {
        TYPE_A if rdlen == 4 => Ok(Rdata::A(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]))),
        TYPE_MX if rdlen >= 3 => {
            let pref = u16::from_be_bytes([rdata[0], rdata[1]]);
            let (exchange, _) = read_name(buf, pos + 2)?;
            Ok(Rdata::Mx { pref, exchange })
        }
        TYPE_TXT => {
            let mut s = String::new();
            let mut i = 0;
            while i < rdata.len() {
                let l = rdata[i] as usize;
                i += 1;
                if i + l > rdata.len() {
                    break;
                }
                s.push_str(&String::from_utf8_lossy(&rdata[i..i + l]));
                i += l;
            }
            Ok(Rdata::Txt(s))
        }
        _ => Ok(Rdata::Other),
    }
}

/// Advance past a (possibly compressed) name, returning the position after it.
fn skip_name(buf: &[u8], mut pos: usize) -> std::io::Result<usize> {
    loop {
        if pos >= buf.len() {
            return Err(short());
        }
        let len = buf[pos];
        if len & 0xc0 == 0xc0 {
            return Ok(pos + 2); // compression pointer ends the name here
        }
        if len == 0 {
            return Ok(pos + 1);
        }
        pos += 1 + len as usize;
    }
}

/// Read a (possibly compressed) name into a dotted string. Returns `(name, next_pos)`.
fn read_name(buf: &[u8], start: usize) -> std::io::Result<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = start;
    let mut next_after: Option<usize> = None;
    let mut hops = 0;
    loop {
        if pos >= buf.len() {
            return Err(short());
        }
        let len = buf[pos];
        if len & 0xc0 == 0xc0 {
            if pos + 1 >= buf.len() {
                return Err(short());
            }
            let ptr = (((len & 0x3f) as usize) << 8) | buf[pos + 1] as usize;
            if next_after.is_none() {
                next_after = Some(pos + 2);
            }
            pos = ptr;
            hops += 1;
            if hops > 32 {
                return Err(std::io::Error::other("dns name compression loop"));
            }
        } else if len == 0 {
            pos += 1;
            break;
        } else {
            let s = pos + 1;
            let e = s + len as usize;
            if e > buf.len() {
                return Err(short());
            }
            labels.push(String::from_utf8_lossy(&buf[s..e]).into_owned());
            pos = e;
        }
    }
    Ok((labels.join("."), next_after.unwrap_or(pos)))
}

fn short() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "truncated dns message")
}
