mod canonical;
mod config;
mod crypto;

use canonical::canonical_request;
use config::{parse_config, SigningKey, VerifierConfig};
use crypto::verify_hex;
use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use std::rc::Rc;
use std::time::{Duration, SystemTime};

const MODULE_VERSION: &str = "0.1.0";
const UNAUTHORIZED_BODY: &[u8] = b"Invalid request signature";

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Info);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> {
        Box::new(SignatureRoot {
            state: Rc::new(ConfigState::default()),
            metrics: None,
        })
    });
}}

#[derive(Clone, Default)]
struct ConfigState {
    config: VerifierConfig,
    error: Option<String>,
}

#[derive(Clone, Default)]
struct MetricIds {
    requests_total: Option<u32>,
    verified_total: Option<u32>,
    rejected_total: Option<u32>,
    config_errors_total: Option<u32>,
}

struct SignatureRoot {
    state: Rc<ConfigState>,
    metrics: Option<MetricIds>,
}

impl Context for SignatureRoot {}

impl RootContext for SignatureRoot {
    fn on_vm_start(&mut self, _vm_configuration_size: usize) -> bool {
        proxy_wasm::hostcalls::log(
            LogLevel::Info,
            &format!("proxy-wasm-signature-verifier v{MODULE_VERSION} starting"),
        )
        .ok();

        self.metrics = Some(MetricIds {
            requests_total: define_counter("signature_verifier_requests_total"),
            verified_total: define_counter("signature_verifier_verified_total"),
            rejected_total: define_counter("signature_verifier_rejected_total"),
            config_errors_total: define_counter("signature_verifier_config_errors_total"),
        });

        true
    }

    fn on_configure(&mut self, _plugin_configuration_size: usize) -> bool {
        let bytes = self.get_plugin_configuration().unwrap_or_default();
        let state = match parse_config(&bytes) {
            Ok(config) => {
                if config.keys.is_empty() {
                    proxy_wasm::hostcalls::log(
                        LogLevel::Warn,
                        "signature-verifier: no signing keys configured; requests will fail closed",
                    )
                    .ok();
                }
                ConfigState {
                    config,
                    error: None,
                }
            }
            Err(error) => {
                proxy_wasm::hostcalls::log(
                    LogLevel::Error,
                    &format!("signature-verifier: {error}"),
                )
                .ok();
                ConfigState {
                    config: VerifierConfig::default(),
                    error: Some(error),
                }
            }
        };

        self.state = Rc::new(state);
        true
    }

    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }

    fn create_http_context(&self, _context_id: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(SignatureFilter {
            state: Rc::clone(&self.state),
            metrics: self.metrics.clone().unwrap_or_default(),
            pending: None,
        }))
    }
}

struct SignatureFilter {
    state: Rc<ConfigState>,
    metrics: MetricIds,
    pending: Option<PendingRequest>,
}

#[derive(Clone, Debug)]
struct PendingRequest {
    method: String,
    path: String,
    timestamp: String,
    signature: String,
    key: SigningKey,
    signed_headers: Vec<(String, String)>,
}

impl Context for SignatureFilter {}

impl HttpContext for SignatureFilter {
    fn on_http_request_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        increment(self.metrics.requests_total);

        if let Some(error) = self.state.error.clone() {
            increment(self.metrics.config_errors_total);
            return self.reject("config-error", Some(error));
        }

        let pending = match self.prepare_pending_request() {
            Ok(pending) => pending,
            Err(reason) => return self.reject(&reason, None),
        };

        if request_has_body(self) {
            self.pending = Some(pending);
            return Action::Continue;
        }

        self.verify_and_mark(pending, b"")
    }

    fn on_http_request_body(&mut self, body_size: usize, end_of_stream: bool) -> Action {
        if !end_of_stream {
            return Action::Continue;
        }

        let Some(pending) = self.pending.take() else {
            return Action::Continue;
        };

        let body = if body_size == 0 {
            Vec::new()
        } else {
            match self.get_http_request_body(0, body_size) {
                Some(bytes) => bytes,
                None => return self.reject("body-unavailable", None),
            }
        };

        self.verify_and_mark(pending, &body)
    }
}

impl SignatureFilter {
    fn prepare_pending_request(&self) -> Result<PendingRequest, String> {
        let config = &self.state.config;
        if config.keys.is_empty() {
            return Err("no-keys-configured".to_string());
        }

        let signature = required_header(self, &config.signature_header, "missing-signature")?;
        let timestamp = required_header(self, &config.timestamp_header, "missing-timestamp")?;
        validate_timestamp(self, &timestamp, config.max_skew_seconds)?;

        let key_id = self
            .get_http_request_header(&config.key_id_header)
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        let key = select_key(config, key_id.as_deref())?;

        let method = property_string(self, vec!["request", "method"])
            .ok_or_else(|| "missing-method".to_string())?;
        let path = property_string(self, vec!["request", "path"])
            .ok_or_else(|| "missing-path".to_string())?;

        let mut signed_headers = Vec::with_capacity(config.signed_headers.len());
        for name in &config.signed_headers {
            let value = required_header(self, name, "missing-signed-header")?;
            signed_headers.push((name.clone(), value));
        }

        Ok(PendingRequest {
            method,
            path,
            timestamp,
            signature,
            key,
            signed_headers,
        })
    }

    fn verify_and_mark(&mut self, pending: PendingRequest, body: &[u8]) -> Action {
        let config = &self.state.config;
        let canonical = canonical_request(
            &pending.method,
            &pending.path,
            &pending.timestamp,
            body,
            &pending.signed_headers,
        );

        if verify_hex(
            pending.key.secret.as_bytes(),
            &canonical,
            pending.signature.as_str(),
        ) {
            increment(self.metrics.verified_total);
            self.mark_request("verified", true, Some(&pending.key.id));
            self.strip_signature_headers();
            Action::Continue
        } else if config.is_report_mode() {
            increment(self.metrics.rejected_total);
            self.mark_request("invalid-signature", false, Some(&pending.key.id));
            self.strip_signature_headers();
            Action::Continue
        } else {
            self.reject("invalid-signature", None)
        }
    }

    fn reject(&mut self, reason: &str, details: Option<String>) -> Action {
        increment(self.metrics.rejected_total);
        self.mark_request(reason, false, None);
        self.strip_signature_headers();

        if self.state.config.is_report_mode() {
            return Action::Continue;
        }

        if let Some(details) = details {
            proxy_wasm::hostcalls::log(
                LogLevel::Warn,
                &format!("signature-verifier: rejecting request: {reason}: {details}"),
            )
            .ok();
        } else {
            proxy_wasm::hostcalls::log(
                LogLevel::Warn,
                &format!("signature-verifier: rejecting request: {reason}"),
            )
            .ok();
        }

        self.send_http_response(
            401,
            vec![(self.state.config.status_header.as_str(), reason)],
            Some(UNAUTHORIZED_BODY),
        );
        Action::Pause
    }

    fn mark_request(&self, status: &str, verified: bool, key_id: Option<&str>) {
        if !self.state.config.emit_headers {
            return;
        }

        let config = &self.state.config;
        self.set_http_request_header(&config.status_header, Some(status));
        self.set_http_request_header(
            &config.verified_header,
            Some(if verified { "true" } else { "false" }),
        );
        if let Some(key_id) = key_id {
            self.set_http_request_header(&config.verified_key_header, Some(key_id));
        }
    }

    fn strip_signature_headers(&self) {
        let config = &self.state.config;
        if !config.strip_signature_headers {
            return;
        }

        self.remove_http_request_header(&config.signature_header);
        self.remove_http_request_header(&config.timestamp_header);
        self.remove_http_request_header(&config.key_id_header);
    }
}

fn define_counter(name: &str) -> Option<u32> {
    proxy_wasm::hostcalls::define_metric(MetricType::Counter, name).ok()
}

fn increment(metric_id: Option<u32>) {
    if let Some(metric_id) = metric_id {
        proxy_wasm::hostcalls::increment_metric(metric_id, 1).ok();
    }
}

fn property_string<C: Context>(ctx: &C, path: Vec<&str>) -> Option<String> {
    ctx.get_property(path)
        .and_then(|bytes| String::from_utf8(bytes).ok())
}

fn required_header<C: HttpContext>(ctx: &C, name: &str, reason: &str) -> Result<String, String> {
    ctx.get_http_request_header(name)
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| reason.to_string())
}

fn request_has_body<C: HttpContext>(ctx: &C) -> bool {
    if ctx
        .get_http_request_header("transfer-encoding")
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false)
    {
        return true;
    }

    ctx.get_http_request_header("content-length")
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map(|length| length > 0)
        .unwrap_or(false)
}

fn validate_timestamp<C: Context>(
    ctx: &C,
    timestamp: &str,
    max_skew_seconds: u64,
) -> Result<(), String> {
    let timestamp_secs = timestamp
        .trim()
        .parse::<u64>()
        .map_err(|_| "invalid-timestamp".to_string())?;

    if max_skew_seconds == 0 {
        return Ok(());
    }

    let now = ctx
        .get_current_time()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs();
    let skew = now.abs_diff(timestamp_secs);
    if skew > max_skew_seconds {
        return Err("timestamp-out-of-window".to_string());
    }

    Ok(())
}

fn select_key(config: &VerifierConfig, key_id: Option<&str>) -> Result<SigningKey, String> {
    if let Some(key_id) = key_id {
        return config
            .keys
            .iter()
            .find(|key| key.id == key_id)
            .cloned()
            .ok_or_else(|| "unknown-key".to_string());
    }

    if config.require_key_id {
        return Err("missing-key-id".to_string());
    }

    config
        .keys
        .first()
        .cloned()
        .ok_or_else(|| "no-keys-configured".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::canonical_request;
    use crate::crypto::sign_hex;

    #[test]
    fn selected_key_requires_known_key_id() {
        let config = VerifierConfig {
            keys: vec![
                SigningKey {
                    id: "old".to_string(),
                    secret: "old-secret".to_string(),
                },
                SigningKey {
                    id: "new".to_string(),
                    secret: "new-secret".to_string(),
                },
            ],
            ..VerifierConfig::default()
        };

        assert_eq!(
            select_key(&config, Some("new")).unwrap().secret,
            "new-secret"
        );
        assert_eq!(
            select_key(&config, Some("missing")).unwrap_err(),
            "unknown-key"
        );
        assert_eq!(select_key(&config, None).unwrap().id, "old");
    }

    #[test]
    fn require_key_id_rejects_implicit_first_key() {
        let config = VerifierConfig {
            keys: vec![SigningKey {
                id: "primary".to_string(),
                secret: "topsecret".to_string(),
            }],
            require_key_id: true,
            ..VerifierConfig::default()
        };

        assert_eq!(select_key(&config, None).unwrap_err(), "missing-key-id");
    }

    #[test]
    fn documents_get_signature_vector() {
        let headers = vec![("host".to_string(), "example.test".to_string())];
        let canonical = canonical_request("GET", "/signed?item=1", "1700000000", b"", &headers);
        assert_eq!(
            sign_hex(b"topsecret", &canonical),
            "e2cedc28442baab59a9be8b5b4436d63e390e197daee39300baddd3c64a9f936"
        );
    }

    #[test]
    fn documents_post_signature_vector() {
        let headers = vec![
            ("host".to_string(), "example.test".to_string()),
            ("content-type".to_string(), "text/plain".to_string()),
        ];
        let canonical = canonical_request("POST", "/upload", "1700000000", b"hello", &headers);
        assert_eq!(
            sign_hex(b"topsecret", &canonical),
            "0b273de061ff8bcc70edfbf8969203b873c0c0f69810c5046f504bed64c5f5f3"
        );
    }
}
