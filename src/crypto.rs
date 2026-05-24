use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

#[cfg(test)]
pub fn sign_hex(secret: &[u8], canonical: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(canonical.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

pub fn verify_hex(secret: &[u8], canonical: &str, signature_header: &str) -> bool {
    let Some(signature) = extract_signature_hex(signature_header) else {
        return false;
    };
    let Ok(signature_bytes) = hex::decode(signature) else {
        return false;
    };

    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(canonical.as_bytes());
    mac.verify_slice(&signature_bytes).is_ok()
}

pub fn extract_signature_hex(header_value: &str) -> Option<String> {
    for part in header_value.split(',') {
        let part = part.trim();
        let candidate = part
            .strip_prefix("v1=")
            .or_else(|| part.strip_prefix("sha256="))
            .or_else(|| part.strip_prefix("hmac-sha256="))
            .unwrap_or(part)
            .trim();

        if candidate.len() == 64 && candidate.as_bytes().iter().all(u8::is_ascii_hexdigit) {
            return Some(candidate.to_ascii_lowercase());
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const CANONICAL: &str = "v1\nGET\n/api?b=2\n1700000000\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\nhost:example.test";

    #[test]
    fn signs_and_verifies() {
        let signature = sign_hex(b"topsecret", CANONICAL);
        assert!(verify_hex(b"topsecret", CANONICAL, &signature));
        assert!(verify_hex(
            b"topsecret",
            CANONICAL,
            &format!("v1={signature}")
        ));
        assert!(!verify_hex(b"wrong", CANONICAL, &signature));
    }

    #[test]
    fn extracts_supported_header_forms() {
        assert_eq!(
            extract_signature_hex(
                "t=1700000000, v1=abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd"
            )
            .as_deref(),
            Some("abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd")
        );
        assert_eq!(
            extract_signature_hex(
                "sha256=ABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD"
            )
            .as_deref(),
            Some("abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd")
        );
        assert!(extract_signature_hex("v1=not-hex").is_none());
    }
}
