use sha2::{Digest, Sha256};

pub fn sha256_hex(body: &[u8]) -> String {
    let digest = Sha256::digest(body);
    hex::encode(digest)
}

pub fn normalize_header_name(name: &str) -> String {
    name.trim().to_ascii_lowercase()
}

pub fn normalize_header_value(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub fn canonical_request(
    method: &str,
    path: &str,
    timestamp: &str,
    body: &[u8],
    signed_headers: &[(String, String)],
) -> String {
    let mut lines = vec![
        "v1".to_string(),
        method.trim().to_ascii_uppercase(),
        path.trim().to_string(),
        timestamp.trim().to_string(),
        sha256_hex(body),
    ];

    for (name, value) in signed_headers {
        lines.push(format!(
            "{}:{}",
            normalize_header_name(name),
            normalize_header_value(value)
        ));
    }

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalizes_empty_body_get() {
        let headers = vec![("Host".to_string(), " Example.TEST ".to_string())];
        let canonical = canonical_request("get", "/api?b=2", "1700000000", b"", &headers);
        assert_eq!(
            canonical,
            "v1\nGET\n/api?b=2\n1700000000\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\nhost:Example.TEST"
        );
    }

    #[test]
    fn collapses_header_whitespace() {
        let headers = vec![(
            "content-type".to_string(),
            " text/plain;  charset=utf-8 ".to_string(),
        )];
        let canonical = canonical_request("POST", "/upload", "1700000000", b"hello", &headers);
        assert!(canonical.ends_with("content-type:text/plain; charset=utf-8"));
        assert!(
            canonical.contains("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
        );
    }
}
