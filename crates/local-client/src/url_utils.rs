use url::Url;

/// Normalize a gateway URL path to a base path suitable for joining REST or WS routes.
///
/// - Strips trailing slashes
/// - Removes `node` or `ws` endpoint suffixes
/// - Ensures the result ends with `/`
pub fn normalize_gateway_base_path(path: &str) -> String {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return "/".to_string();
    }

    let mut segments: Vec<&str> = trimmed.split('/').filter(|seg| !seg.is_empty()).collect();
    if matches!(segments.last().copied(), Some("node") | Some("ws")) {
        segments.pop();
    }

    if segments.is_empty() {
        "/".to_string()
    } else {
        format!("/{}/", segments.join("/"))
    }
}

/// Canonical key for storing gateway-scoped settings (for example known-host pins).
/// It normalizes scheme variants and path suffixes so equivalent URLs map to one key.
pub fn canonical_gateway_key(gateway_url: &str) -> Result<String, String> {
    let url = Url::parse(gateway_url).map_err(|e| format!("invalid gateway URL: {e}"))?;
    let tls_scope = match url.scheme() {
        "wss" | "https" => "tls",
        "ws" | "http" => "plain",
        other => return Err(format!("unsupported scheme '{other}'")),
    };
    let host = url
        .host_str()
        .ok_or_else(|| "gateway URL is missing host".to_string())?
        .to_ascii_lowercase();
    let port = url
        .port_or_known_default()
        .ok_or_else(|| "gateway URL is missing port".to_string())?;
    let path = normalize_gateway_base_path(url.path());
    Ok(format!("{tls_scope}://{host}:{port}{path}"))
}

/// Convert a gateway URL to an HTTP base URL for REST calls.
/// ws:// → http://, wss:// → https://, http/https pass through.
/// Clears query/fragment and ensures path ends with '/' for joining REST routes.
pub fn normalize_http_url(gateway_url: &str) -> Result<Url, Box<dyn std::error::Error>> {
    let mut url = Url::parse(gateway_url)?;
    match url.scheme() {
        "ws" => {
            if url.set_scheme("http").is_err() {
                return Err("failed to convert ws URL to http".into());
            }
        }
        "wss" => {
            if url.set_scheme("https").is_err() {
                return Err("failed to convert wss URL to https".into());
            }
        }
        "http" | "https" => {}
        s => return Err(format!("unsupported scheme '{s}'").into()),
    }

    url.set_query(None);
    url.set_fragment(None);

    let path = normalize_gateway_base_path(url.path());
    url.set_path(&path);

    Ok(url)
}

/// Validate that a fingerprint is only used with TLS transports.
/// Accepts both post-HTTP-normalization (https) and post-WS-normalization (wss) URLs.
pub fn validate_fingerprint_transport(
    url: &Url,
    fingerprint: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    if fingerprint.is_some() && !matches!(url.scheme(), "https" | "wss") {
        return Err("--fingerprint requires a TLS gateway (wss:// or https:// input URL)".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_path() {
        assert_eq!(normalize_gateway_base_path("/"), "/");
    }

    #[test]
    fn empty_path() {
        assert_eq!(normalize_gateway_base_path(""), "/");
    }

    #[test]
    fn base_path_gets_trailing_slash() {
        assert_eq!(normalize_gateway_base_path("/gateway"), "/gateway/");
    }

    #[test]
    fn strips_node_suffix() {
        assert_eq!(normalize_gateway_base_path("/gateway/node"), "/gateway/");
    }

    #[test]
    fn strips_ws_suffix() {
        assert_eq!(normalize_gateway_base_path("/api/ws"), "/api/");
    }

    #[test]
    fn strips_trailing_slashes() {
        assert_eq!(normalize_gateway_base_path("/gateway///"), "/gateway/");
    }

    #[test]
    fn node_only_becomes_root() {
        assert_eq!(normalize_gateway_base_path("/node"), "/");
    }

    #[test]
    fn canonical_gateway_key_unifies_equivalent_tls_urls() {
        let k1 = canonical_gateway_key("wss://Example.com:8443/gateway").unwrap();
        let k2 = canonical_gateway_key("https://example.com:8443/gateway/node").unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn canonical_gateway_key_unifies_equivalent_plain_urls() {
        let k1 = canonical_gateway_key("ws://example.com:8080/api/ws").unwrap();
        let k2 = canonical_gateway_key("http://example.com:8080/api").unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn canonical_gateway_key_rejects_unknown_scheme() {
        let err = canonical_gateway_key("ftp://example.com").unwrap_err();
        assert!(err.contains("unsupported scheme"));
    }

    // --- normalize_http_url ---

    #[test]
    fn normalize_ws_to_http() {
        let result = normalize_http_url("ws://localhost:8443").unwrap();
        assert_eq!(result.as_str(), "http://localhost:8443/");
    }

    #[test]
    fn normalize_wss_to_https() {
        let result = normalize_http_url("wss://example.com:443/gateway").unwrap();
        assert_eq!(result.as_str(), "https://example.com/gateway/");
    }

    #[test]
    fn normalize_http_passthrough() {
        let result = normalize_http_url("http://10.0.0.1:8080").unwrap();
        assert_eq!(result.as_str(), "http://10.0.0.1:8080/");
    }

    #[test]
    fn normalize_strips_query_and_fragment() {
        let result = normalize_http_url("ws://localhost:8443/base?x=1#frag").unwrap();
        assert_eq!(result.as_str(), "http://localhost:8443/base/");
    }

    #[test]
    fn normalize_strips_node_endpoint_segment() {
        let result = normalize_http_url("ws://localhost:8443/node").unwrap();
        assert_eq!(result.as_str(), "http://localhost:8443/");
    }

    #[test]
    fn normalize_strips_prefixed_node_endpoint_segment() {
        let result = normalize_http_url("wss://example.com/gateway/node").unwrap();
        assert_eq!(result.as_str(), "https://example.com/gateway/");
    }

    #[test]
    fn normalize_strips_ws_endpoint_segment() {
        let result = normalize_http_url("wss://example.com/api/ws").unwrap();
        assert_eq!(result.as_str(), "https://example.com/api/");
    }

    #[test]
    fn normalize_bad_scheme_rejected() {
        let result = normalize_http_url("ftp://example.com");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("unsupported scheme"));
    }

    // --- validate_fingerprint_transport ---

    #[test]
    fn fingerprint_rejected_for_plain_http_transport() {
        let url = Url::parse("http://example.com:8443/").unwrap();
        let err = validate_fingerprint_transport(&url, Some("SHA256:ab")).unwrap_err();
        assert!(err
            .to_string()
            .contains("--fingerprint requires a TLS gateway"));
    }

    #[test]
    fn fingerprint_allowed_for_https_transport() {
        let url = Url::parse("https://example.com:8443/").unwrap();
        validate_fingerprint_transport(&url, Some("SHA256:ab")).unwrap();
    }

    #[test]
    fn fingerprint_rejected_for_plain_ws_transport() {
        let url = Url::parse("ws://example.com:8443/node").unwrap();
        let err = validate_fingerprint_transport(&url, Some("SHA256:ab")).unwrap_err();
        assert!(err
            .to_string()
            .contains("--fingerprint requires a TLS gateway"));
    }

    #[test]
    fn fingerprint_allowed_for_wss_transport() {
        let url = Url::parse("wss://example.com:8443/node").unwrap();
        validate_fingerprint_transport(&url, Some("SHA256:ab")).unwrap();
    }
}
