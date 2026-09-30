//! Authentication + RBAC for the dashboard and JSON API (F4.4).
//!
//! Two mechanisms, combinable via `[server.auth] mode`:
//!
//! - **password**: Argon2id login (`POST /api/login`) issuing an HMAC-SHA256
//!   signed session cookie (`sentry_session`).
//! - **token**: static bearer tokens, stored as SHA-256 hashes in config.
//!
//! Roles: `admin` may mutate (block/unblock/forgive/resolve/ack); `viewer`
//! is read-only. `mode = "none"` disables all checks (loopback only).

use std::fmt;
use std::sync::LazyLock;

use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use hmac::{Hmac, Mac};
use sentry_core::config::{SentryConfig, ServerAuthConfig};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Hash verified against failed logins for unknown usernames, so response
/// timing does not trivially reveal whether a user exists.
static DUMMY_HASH: LazyLock<String> = LazyLock::new(|| {
    Argon2::default()
        .hash_password(b"sentry-unknown-user", &SaltString::generate(&mut OsRng))
        .map(|h| h.to_string())
        .unwrap_or_default()
});

/// Access role carried by an identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// May read and mutate (block/unblock/forgive/resolve/ack).
    Admin,
    /// Read-only.
    Viewer,
}

impl Role {
    /// Whether this role may perform mutations.
    pub fn allows_mutation(self) -> bool {
        matches!(self, Role::Admin)
    }

    /// Lowercase stable name.
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::Viewer => "viewer",
        }
    }

    fn parse(s: &str) -> Role {
        if s.eq_ignore_ascii_case("admin") {
            Role::Admin
        } else {
            Role::Viewer
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Authenticated principal attached to a request.
#[derive(Debug, Clone)]
pub struct Identity {
    /// Display name (username or `token:<n>`).
    pub username: String,
    /// Access role.
    pub role: Role,
}

/// Which auth mechanisms are active.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthMode {
    None,
    Password,
    Token,
    Both,
}

impl AuthMode {
    fn parse(s: &str) -> color_eyre::Result<AuthMode> {
        match s.to_ascii_lowercase().as_str() {
            "" | "none" => Ok(AuthMode::None),
            "password" => Ok(AuthMode::Password),
            "token" => Ok(AuthMode::Token),
            "both" => Ok(AuthMode::Both),
            other => Err(color_eyre::eyre::eyre!(
                "invalid [server.auth] mode `{other}` (expected none | password | token | both)"
            )),
        }
    }

    fn accepts_password(self) -> bool {
        matches!(self, AuthMode::Password | AuthMode::Both)
    }

    fn accepts_token(self) -> bool {
        matches!(self, AuthMode::Token | AuthMode::Both)
    }
}

#[derive(Debug)]
struct AuthUser {
    username: String,
    password_hash: String,
    role: Role,
}

#[derive(Debug)]
struct AuthToken {
    hash: [u8; 32],
    role: Role,
    label: String,
}

/// Immutable auth state built once at server startup.
#[derive(Debug)]
pub struct AuthLayer {
    mode: AuthMode,
    users: Vec<AuthUser>,
    tokens: Vec<AuthToken>,
    session_key: Option<Vec<u8>>,
    session_ttl_secs: u64,
}

impl AuthLayer {
    /// Build the auth layer from `[server]` / `[server.auth]` config.
    ///
    /// Fails when the selected mode is unusable (no users/tokens configured,
    /// malformed hashes, or a missing session secret env var).
    pub fn from_config(cfg: &SentryConfig) -> color_eyre::Result<AuthLayer> {
        let auth: &ServerAuthConfig = &cfg.server.auth;
        let mode = AuthMode::parse(&auth.mode)?;

        let mut users = Vec::new();
        for u in &auth.users {
            if u.username.is_empty() {
                return Err(color_eyre::eyre::eyre!(
                    "[server.auth] user with empty username"
                ));
            }
            PasswordHash::new(&u.password_hash).map_err(|e| {
                color_eyre::eyre::eyre!(
                    "[server.auth] user `{}` has an invalid Argon2 hash: {e} (generate one with `sentry auth hash-password`)",
                    u.username
                )
            })?;
            users.push(AuthUser {
                username: u.username.clone(),
                password_hash: u.password_hash.clone(),
                role: Role::parse(&u.role),
            });
        }

        let mut tokens = Vec::new();
        for (idx, t) in auth.tokens.iter().enumerate() {
            let raw = if !t.token_sha256.is_empty() {
                parse_sha256_hex(&t.token_sha256).ok_or_else(|| {
                    color_eyre::eyre::eyre!(
                        "[server.auth] token #{idx}: token_sha256 must be 64 hex chars (sha256 of the raw token)"
                    )
                })?
            } else if !t.token_env.is_empty() {
                let val = std::env::var(&t.token_env).unwrap_or_default();
                if val.trim().is_empty() {
                    return Err(color_eyre::eyre::eyre!(
                        "[server.auth] token #{idx}: env var {} is not set",
                        t.token_env
                    ));
                }
                Sha256::digest(val.trim().as_bytes()).into()
            } else {
                return Err(color_eyre::eyre::eyre!(
                    "[server.auth] token #{idx}: set either token_sha256 or token_env"
                ));
            };
            tokens.push(AuthToken {
                hash: raw,
                role: Role::parse(&t.role),
                label: format!("token:{idx}"),
            });
        }

        if mode.accepts_password() {
            if users.is_empty() {
                return Err(color_eyre::eyre::eyre!(
                    "[server.auth] mode `{}` requires at least one [[server.auth.users]] entry",
                    auth.mode
                ));
            }
            let secret = std::env::var(&auth.session_secret_env).unwrap_or_default();
            if secret.trim().is_empty() {
                return Err(color_eyre::eyre::eyre!(
                    "[server.auth] password mode requires the session secret env var `{}` (32+ random bytes)",
                    auth.session_secret_env
                ));
            }
            if secret.trim().len() < 16 {
                tracing::warn!(
                    "[server.auth] session secret is short (<16 chars); use 32+ random bytes"
                );
            }
        }

        if mode.accepts_token() && tokens.is_empty() {
            return Err(color_eyre::eyre::eyre!(
                "[server.auth] mode `{}` requires at least one [[server.auth.tokens]] entry",
                auth.mode
            ));
        }

        let session_key = if mode.accepts_password() {
            Some(
                std::env::var(&auth.session_secret_env)
                    .unwrap_or_default()
                    .into_bytes(),
            )
        } else {
            None
        };

        Ok(AuthLayer {
            mode,
            users,
            tokens,
            session_key,
            session_ttl_secs: auth.session_ttl_secs,
        })
    }

    /// Auth entirely disabled (`mode = "none"`): every request is anonymous.
    pub fn disabled(&self) -> bool {
        self.mode == AuthMode::None
    }

    /// Whether password login may be attempted.
    pub fn password_login_enabled(&self) -> bool {
        self.mode.accepts_password()
    }

    /// Whether token auth may be attempted.
    pub fn token_auth_enabled(&self) -> bool {
        self.mode.accepts_token()
    }

    /// Resolve an identity from a bearer token and/or session cookie value.
    ///
    /// Token auth wins when both are presented; an invalid token does not
    /// veto a valid session.
    pub fn identify(&self, bearer: Option<&str>, session_cookie: Option<&str>) -> Option<Identity> {
        if let (true, Some(token)) = (self.mode.accepts_token(), bearer) {
            if let Some(id) = self.identify_token(token) {
                return Some(id);
            }
        }
        if let (true, Some(cookie)) = (self.mode.accepts_password(), session_cookie) {
            if let Some(id) = self.verify_session(cookie) {
                return Some(id);
            }
        }
        None
    }

    fn identify_token(&self, token: &str) -> Option<Identity> {
        let hash: [u8; 32] = Sha256::digest(token.trim().as_bytes()).into();
        self.tokens
            .iter()
            .find(|t| t.hash == hash)
            .map(|t| Identity {
                username: t.label.clone(),
                role: t.role,
            })
    }

    /// Verify a username/password pair, returning the user's role.
    ///
    /// Always `None` when password auth is not enabled for this layer.
    pub fn verify_password_login(&self, username: &str, password: &str) -> Option<Role> {
        if !self.mode.accepts_password() {
            return None;
        }
        match self.users.iter().find(|u| u.username == username) {
            Some(user) => {
                if verify_argon2(&user.password_hash, password) {
                    Some(user.role)
                } else {
                    None
                }
            }
            None => {
                // Burn equivalent Argon2 work for unknown users too.
                let _ = verify_argon2(&DUMMY_HASH, password);
                None
            }
        }
    }

    /// Issue a signed session cookie value for `username`.
    pub fn issue_session(&self, username: &str) -> Option<String> {
        let key = self.session_key.as_ref()?;
        let user_hex = hex_encode(username.as_bytes());
        let expiry = now_unix() + self.session_ttl_secs as i64;
        let payload = format!("{user_hex}.{expiry}");
        Some(format!("{}.{}", payload, sign(key, &payload)))
    }

    /// Verify a session cookie value, returning the identity.
    pub fn verify_session(&self, value: &str) -> Option<Identity> {
        let key = self.session_key.as_ref()?;
        let mut parts = value.rsplitn(3, '.');
        let sig = parts.next()?;
        let expiry: i64 = parts.next()?.parse().ok()?;
        let user_hex = parts.next()?;
        let payload = format!("{user_hex}.{expiry}");
        if !constant_time_eq(sign(key, &payload).as_bytes(), sig.as_bytes()) {
            return None;
        }
        if now_unix() > expiry {
            return None;
        }
        let username = String::from_utf8(hex_decode(user_hex)?).ok()?;
        let user = self.users.iter().find(|u| u.username == username)?;
        Some(Identity {
            username,
            role: user.role,
        })
    }

    /// Session cookie name (`sentry_session`).
    pub fn cookie_name(&self) -> &'static str {
        "sentry_session"
    }

    /// Session TTL in seconds.
    pub fn session_ttl_secs(&self) -> u64 {
        self.session_ttl_secs
    }
}

fn verify_argon2(phc: &str, password: &str) -> bool {
    let Some(parsed) = PasswordHash::new(phc).ok() else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

fn sign(key: &[u8], payload: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(payload.as_bytes());
    hex_encode(&mac.finalize().into_bytes())
}

fn now_unix() -> i64 {
    chrono::Utc::now().timestamp()
}

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok())
        .collect()
}

fn parse_sha256_hex(s: &str) -> Option<[u8; 32]> {
    let bytes = hex_decode(s.trim())?;
    bytes.try_into().ok()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

/// Generate an Argon2id PHC string for `[server.auth.users]` (CLI helper).
pub fn hash_password(password: &str) -> color_eyre::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| color_eyre::eyre::eyre!("argon2 hash failed: {e}"))
}

/// Hex SHA-256 of a raw token (CLI helper for `[server.auth.tokens]`).
pub fn token_hash(token: &str) -> String {
    hex_encode(&Sha256::digest(token.trim().as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentry_core::config::{AuthTokenConfig, AuthUserConfig, ServerConfig};

    fn server_cfg(auth: ServerAuthConfig) -> SentryConfig {
        SentryConfig {
            server: ServerConfig {
                auth,
                ..ServerConfig::default()
            },
            ..SentryConfig::default()
        }
    }

    fn phc(password: &str) -> String {
        Argon2::default()
            .hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng))
            .unwrap()
            .to_string()
    }

    fn auth_config(mode: &str, secret_env: Option<String>) -> ServerAuthConfig {
        ServerAuthConfig {
            mode: mode.to_string(),
            users: vec![AuthUserConfig {
                username: "alice".to_string(),
                password_hash: phc("s3cret"),
                role: "admin".to_string(),
            }],
            tokens: vec![AuthTokenConfig {
                token_sha256: token_hash("tok123"),
                token_env: String::new(),
                role: "viewer".to_string(),
            }],
            session_secret_env: secret_env.unwrap_or_default(),
            session_ttl_secs: 60,
        }
    }

    #[test]
    fn mode_none_is_disabled() {
        let layer = AuthLayer::from_config(&server_cfg(auth_config("none", None))).unwrap();
        assert!(layer.disabled());
        assert!(!layer.password_login_enabled());
        assert!(!layer.token_auth_enabled());
    }

    #[test]
    fn invalid_mode_fails_at_startup() {
        let err = AuthLayer::from_config(&server_cfg(auth_config("magic", None))).unwrap_err();
        assert!(err.to_string().contains("invalid [server.auth] mode"));
    }

    #[test]
    fn token_identify_matches_hash_and_rejects_unknown() {
        let layer = AuthLayer::from_config(&server_cfg(auth_config("token", None))).unwrap();
        let id = layer.identify(Some("tok123"), None).expect("valid token");
        assert_eq!(id.role, Role::Viewer);
        assert_eq!(id.username, "token:0");
        assert!(layer.identify(Some("wrong"), None).is_none());
    }

    #[test]
    fn token_mode_ignores_password_login() {
        let layer = AuthLayer::from_config(&server_cfg(auth_config("token", None))).unwrap();
        assert!(!layer.password_login_enabled());
        assert!(layer.verify_password_login("alice", "s3cret").is_none());
    }

    #[test]
    fn password_login_verifies_argon2() {
        std::env::set_var("SENTRY_TEST_SECRET_PW", "0123456789abcdef0123456789abcdef");
        let cfg = auth_config("password", Some("SENTRY_TEST_SECRET_PW".into()));
        let layer = AuthLayer::from_config(&server_cfg(cfg)).unwrap();
        assert_eq!(
            layer.verify_password_login("alice", "s3cret"),
            Some(Role::Admin)
        );
        assert_eq!(layer.verify_password_login("alice", "wrong"), None);
        // Unknown user: no identity, but still burns Argon2 work.
        assert_eq!(layer.verify_password_login("mallory", "s3cret"), None);
        std::env::remove_var("SENTRY_TEST_SECRET_PW");
    }

    #[test]
    fn password_mode_requires_secret_env() {
        let cfg = auth_config("password", Some("SENTRY_TEST_MISSING_SECRET_XYZ".into()));
        assert!(AuthLayer::from_config(&server_cfg(cfg)).is_err());
    }

    #[test]
    fn session_roundtrip_and_tamper_rejection() {
        std::env::set_var("SENTRY_TEST_SECRET_RT", "0123456789abcdef0123456789abcdef");
        let cfg = auth_config("password", Some("SENTRY_TEST_SECRET_RT".into()));
        let layer = AuthLayer::from_config(&server_cfg(cfg)).unwrap();
        let cookie = layer.issue_session("alice").unwrap();
        let id = layer.verify_session(&cookie).expect("valid session");
        assert_eq!(id.username, "alice");
        assert_eq!(id.role, Role::Admin);

        let mut tampered = cookie.clone();
        tampered.replace_range(0..1, "f");
        assert!(layer.verify_session(&tampered).is_none());
        assert!(layer.verify_session(&format!("{cookie}x")).is_none());
        assert!(layer.verify_session("garbage").is_none());
        assert!(layer
            .verify_session("dW5rbm93bg==.9999999999.deadbeef")
            .is_none());
        std::env::remove_var("SENTRY_TEST_SECRET_RT");
    }

    #[test]
    fn both_mode_accepts_token_and_session() {
        std::env::set_var(
            "SENTRY_TEST_SECRET_BOTH",
            "0123456789abcdef0123456789abcdef",
        );
        let cfg = auth_config("both", Some("SENTRY_TEST_SECRET_BOTH".into()));
        let layer = AuthLayer::from_config(&server_cfg(cfg)).unwrap();
        let id = layer
            .identify(Some("tok123"), None)
            .expect("token identity");
        assert_eq!(id.username, "token:0");
        let cookie = layer.issue_session("alice").unwrap();
        let id = layer
            .identify(None, Some(&cookie))
            .expect("session identity");
        assert_eq!(id.username, "alice");
        // An invalid bearer does not veto a valid session.
        let id = layer
            .identify(Some("nope"), Some(&cookie))
            .expect("session fallback");
        assert_eq!(id.username, "alice");
        std::env::remove_var("SENTRY_TEST_SECRET_BOTH");
    }

    #[test]
    fn expired_session_is_rejected() {
        std::env::set_var("SENTRY_TEST_SECRET_EXP", "0123456789abcdef0123456789abcdef");
        let mut cfg = auth_config("password", Some("SENTRY_TEST_SECRET_EXP".into()));
        cfg.session_ttl_secs = 0;
        let layer = AuthLayer::from_config(&server_cfg(cfg)).unwrap();
        let cookie = layer.issue_session("alice").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1100));
        assert!(layer.verify_session(&cookie).is_none());
        std::env::remove_var("SENTRY_TEST_SECRET_EXP");
    }

    #[test]
    fn hex_roundtrip() {
        let enc = hex_encode(b"\xde\xad\xbe\xef");
        assert_eq!(enc, "deadbeef");
        assert_eq!(hex_decode(&enc).unwrap(), b"\xde\xad\xbe\xef");
        assert!(hex_decode("abc").is_none());
        assert!(parse_sha256_hex(&token_hash("tok123")).is_some());
    }

    #[test]
    fn role_parsing_defaults_to_viewer() {
        assert_eq!(Role::parse("admin"), Role::Admin);
        assert_eq!(Role::parse("ADMIN"), Role::Admin);
        assert_eq!(Role::parse("whatever"), Role::Viewer);
        assert!(Role::Admin.allows_mutation());
        assert!(!Role::Viewer.allows_mutation());
        assert_eq!(Role::Admin.to_string(), "admin");
    }
}
