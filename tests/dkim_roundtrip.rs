//! DKIM sign/verify round-trip.
//!
//! 1. A generated 2048-bit key: sign then verify against the matching public key (and prove a
//!    body tamper breaks the signature).
//! 2. THE REAL OpenDKIM key: sign with `/etc/opendkim/keys/w33d.xyz/default.private` and verify
//!    the signature against the params published in `default.txt` (`default._domainkey.w33d.xyz`).
//!    This proves outbound mail keeps verifying against the EXISTING DNS record with zero change.
//!    Skips gracefully when the key/record are not present (e.g. CI without the host files).

use std::fs;

use corvid::dkim::{self, DkimSigner};
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::{RsaPrivateKey, RsaPublicKey};

const MSG: &str = "From: HOLDFAST <w33d@w33d.xyz>\r\n\
To: Bob <bob@example.com>\r\n\
Subject: Corvid DKIM test\r\n\
Date: Mon, 29 Jun 2026 12:00:00 +0000\r\n\
Message-ID: <corvid-test@w33d.xyz>\r\n\
MIME-Version: 1.0\r\n\
Content-Type: text/plain; charset=utf-8\r\n\
\r\n\
Hello from Corvid.\r\n\
This body is covered by the body hash.\r\n";

#[test]
fn sign_verify_roundtrip_generated_key() {
    let mut rng = rand::thread_rng();
    let key = RsaPrivateKey::new(&mut rng, 2048).expect("generate key");
    let pem = key.to_pkcs8_pem(LineEnding::LF).expect("encode pkcs8");

    let signer = DkimSigner::from_pkcs8_pem(&pem, "test", "w33d.xyz").expect("signer");
    let signed = signer.sign_at(MSG, 1_700_000_000).expect("sign");
    assert!(signed.starts_with("DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;"));

    let der = RsaPublicKey::from(&key).to_public_key_der().expect("spki der");
    assert!(dkim::verify(&signed, der.as_bytes()).expect("verify"), "fresh signature must verify");

    // Tampering the body must break the body hash -> verification fails.
    let tampered = signed.replace("Hello from Corvid.", "Hello from ATTACKER.");
    assert!(!dkim::verify(&tampered, der.as_bytes()).expect("verify tampered"));

    // Tampering a signed header must break the signature too.
    let tampered2 = signed.replace("Subject: Corvid DKIM test", "Subject: Evil");
    assert!(!dkim::verify(&tampered2, der.as_bytes()).expect("verify tampered2"));
}

#[test]
fn sign_with_real_opendkim_key_verifies_against_published_txt() {
    let key_path = "/etc/opendkim/keys/w33d.xyz/default.private";
    let txt_path = "/etc/opendkim/keys/w33d.xyz/default.txt";

    let (Ok(_), Ok(txt)) = (fs::read_to_string(key_path), fs::read_to_string(txt_path)) else {
        eprintln!("NOTE: {key_path} / {txt_path} not readable — skipping real-key DKIM test.");
        return;
    };

    let signer = DkimSigner::from_key_file(key_path, "default", "w33d.xyz").expect("load real key");
    let signed = signer.sign(MSG).expect("sign with real key");

    let p = dkim::extract_p_from_txt(&txt).expect("p= in default.txt");
    let der = dkim::public_key_der_from_p(&p).expect("decode published public key");

    assert!(
        dkim::verify(&signed, &der).expect("verify against published key"),
        "outbound signature must verify against the PUBLISHED default._domainkey.w33d.xyz key"
    );
    eprintln!("REAL-KEY DKIM OK: signature verifies against published default._domainkey.w33d.xyz");
}
