use serde::Deserialize;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SigningKey {
    pub id: String,
    pub secret: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct VerifierConfig {
    #[serde(default)]
    pub keys: Vec<SigningKey>,
    #[serde(default = "default_signature_header")]
    pub signature_header: String,
    #[serde(default = "default_timestamp_header")]
    pub timestamp_header: String,
    #[serde(default = "default_key_id_header")]
    pub key_id_header: String,
    #[serde(default = "default_status_header")]
    pub status_header: String,
    #[serde(default = "default_verified_header")]
    pub verified_header: String,
    #[serde(default = "default_verified_key_header")]
    pub verified_key_header: String,
    #[serde(default = "default_signed_headers")]
    pub signed_headers: Vec<String>,
    #[serde(default = "default_max_skew_seconds")]
    pub max_skew_seconds: u64,
    #[serde(default = "default_mode")]
    pub mode: String,
    #[serde(default)]
    pub require_key_id: bool,
    #[serde(default = "default_true")]
    pub emit_headers: bool,
    #[serde(default = "default_true")]
    pub strip_signature_headers: bool,
}

impl Default for VerifierConfig {
    fn default() -> Self {
        Self {
            keys: Vec::new(),
            signature_header: default_signature_header(),
            timestamp_header: default_timestamp_header(),
            key_id_header: default_key_id_header(),
            status_header: default_status_header(),
            verified_header: default_verified_header(),
            verified_key_header: default_verified_key_header(),
            signed_headers: default_signed_headers(),
            max_skew_seconds: default_max_skew_seconds(),
            mode: default_mode(),
            require_key_id: false,
            emit_headers: true,
            strip_signature_headers: true,
        }
    }
}

impl VerifierConfig {
    pub fn is_report_mode(&self) -> bool {
        self.mode.eq_ignore_ascii_case("report")
    }
}

pub fn parse_config(data: &[u8]) -> Result<VerifierConfig, String> {
    if data.is_empty() {
        return Ok(VerifierConfig::default());
    }

    let config: VerifierConfig =
        serde_json_wasm::from_slice(data).map_err(|err| format!("invalid-config: {err}"))?;

    if config.mode != "enforce" && config.mode != "report" {
        return Err("invalid-config: mode must be enforce or report".to_string());
    }

    if config
        .signed_headers
        .iter()
        .any(|name| name.trim().is_empty())
    {
        return Err("invalid-config: signed_headers contains an empty name".to_string());
    }

    Ok(config)
}

fn default_signature_header() -> String {
    "x-signature".to_string()
}

fn default_timestamp_header() -> String {
    "x-signature-timestamp".to_string()
}

fn default_key_id_header() -> String {
    "x-signature-key-id".to_string()
}

fn default_status_header() -> String {
    "x-signature-status".to_string()
}

fn default_verified_header() -> String {
    "x-signature-verified".to_string()
}

fn default_verified_key_header() -> String {
    "x-verified-signature-key".to_string()
}

fn default_signed_headers() -> Vec<String> {
    vec!["host".to_string()]
}

fn default_max_skew_seconds() -> u64 {
    300
}

fn default_mode() -> String {
    "enforce".to_string()
}

fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_safe_for_enforcement() {
        let config = VerifierConfig::default();
        assert_eq!(config.signature_header, "x-signature");
        assert_eq!(config.timestamp_header, "x-signature-timestamp");
        assert_eq!(config.signed_headers, vec!["host"]);
        assert_eq!(config.max_skew_seconds, 300);
        assert_eq!(config.mode, "enforce");
        assert!(config.emit_headers);
        assert!(config.strip_signature_headers);
    }

    #[test]
    fn parses_full_config() {
        let json = br#"{
            "keys":[{"id":"primary","secret":"topsecret"}],
            "signed_headers":["host","content-type"],
            "max_skew_seconds":0,
            "mode":"report",
            "require_key_id":true,
            "emit_headers":false,
            "strip_signature_headers":false
        }"#;
        let config = parse_config(json).unwrap();
        assert_eq!(config.keys[0].id, "primary");
        assert_eq!(config.signed_headers, vec!["host", "content-type"]);
        assert_eq!(config.max_skew_seconds, 0);
        assert_eq!(config.mode, "report");
        assert!(config.require_key_id);
        assert!(!config.emit_headers);
        assert!(!config.strip_signature_headers);
    }

    #[test]
    fn rejects_invalid_mode() {
        let err = parse_config(br#"{"mode":"observe"}"#).unwrap_err();
        assert!(err.contains("mode"));
    }
}
