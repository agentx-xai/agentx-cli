use crate::domain::{RemotePlan, TeamManifestDocument, validate_sha256, validate_workspace_id};
use anyhow::{Context, Result, anyhow, bail};
use directories::BaseDirs;
use reqwest::{
    Url,
    blocking::{Client, Response, multipart},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    path::PathBuf,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const MAX_JSON_RESPONSE_BYTES: usize = 2 << 20;
const MAX_ERROR_RESPONSE_BYTES: usize = 64 << 10;
const MAX_ERROR_DISPLAY_CHARS: usize = 1024;
const MAX_ARTIFACT_BYTES: usize = 51 << 20;
const MAX_RELEASE_PAGES: usize = 100;
const MAX_CREDENTIAL_BYTES: u64 = 32 << 10;

#[derive(Debug, Serialize, Deserialize)]
struct RegistryCredentials {
    url: String,
    token: String,
    #[serde(default)]
    workspace_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expires_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    oidc: Option<OIDCCredentials>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct OIDCCredentials {
    issuer: String,
    client_id: String,
    scope: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    audience: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OIDCClientConfig {
    issuer: String,
    client_id: String,
    scope: String,
    #[serde(default)]
    audience: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OIDCDiscovery {
    issuer: String,
    token_endpoint: String,
    device_authorization_endpoint: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DeviceAuthorizationResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    #[serde(default)]
    verification_uri_complete: Option<String>,
    expires_in: u64,
    #[serde(default = "default_device_poll_interval")]
    interval: u64,
}

#[derive(Debug, Deserialize)]
struct OAuthTokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,
    #[serde(default)]
    refresh_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OAuthErrorResponse {
    error: String,
    #[serde(default)]
    error_description: String,
}

pub(crate) struct DeviceAuthorization {
    http: Client,
    registry_url: Url,
    workspace_id: Option<String>,
    oidc: OIDCCredentials,
    token_endpoint: Url,
    device_code: String,
    user_code: String,
    verification_uri: Url,
    verification_uri_complete: Option<Url>,
    deadline: Instant,
    interval: Duration,
}

#[derive(Debug, Deserialize)]
struct RemoteRelease {
    name: String,
    version: String,
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RemoteReleasePage {
    Legacy(Vec<RemoteRelease>),
    Paged {
        items: Vec<RemoteRelease>,
        #[serde(default)]
        next_cursor: Option<String>,
    },
}

#[derive(Debug, Deserialize)]
pub(crate) struct RemoteWorkspace {
    pub(crate) id: String,
    pub(crate) slug: String,
    pub(crate) name: String,
}

#[derive(Debug, Deserialize)]
struct RemoteWorkspacePage {
    items: Vec<RemoteWorkspace>,
    #[serde(default)]
    next_cursor: Option<String>,
}

pub(crate) struct RegistryClient {
    http: Client,
    base_url: Url,
    token: String,
    workspace_id: Option<String>,
}

impl DeviceAuthorization {
    pub(crate) fn verification_url(&self) -> &str {
        self.verification_uri_complete
            .as_ref()
            .unwrap_or(&self.verification_uri)
            .as_str()
    }

    pub(crate) fn user_code(&self) -> &str {
        &self.user_code
    }

    pub(crate) fn finish(mut self) -> Result<PathBuf> {
        loop {
            if Instant::now() >= self.deadline {
                bail!(
                    "OIDC device authorization expired; run `agentx registry login --oidc` again"
                );
            }
            thread::sleep(self.interval);
            let response = self
                .http
                .post(self.token_endpoint.clone())
                .form(&[
                    ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                    ("device_code", self.device_code.as_str()),
                    ("client_id", self.oidc.client_id.as_str()),
                ])
                .send()
                .context("OIDC device token request failed")?;
            if response.status().is_success() {
                let token: OAuthTokenResponse = decode_json_response(response, "OIDC token")?;
                validate_oauth_token(&token)?;
                let credentials = RegistryCredentials {
                    url: self.registry_url.as_str().trim_end_matches('/').to_string(),
                    token: token.access_token,
                    workspace_id: self.workspace_id,
                    refresh_token: token.refresh_token,
                    expires_at: Some(unix_time()?.saturating_add(token.expires_in)),
                    oidc: Some(self.oidc),
                };
                return save_credentials(&credentials);
            }
            let status = response.status();
            let error: OAuthErrorResponse = decode_json_response(response, "OIDC error")
                .with_context(|| format!("OIDC token endpoint returned {status}"))?;
            match error.error.as_str() {
                "authorization_pending" => {}
                "slow_down" => {
                    self.interval =
                        (self.interval + Duration::from_secs(5)).min(Duration::from_secs(30));
                }
                "access_denied" => bail!("OIDC device authorization was denied"),
                "expired_token" => bail!("OIDC device authorization expired"),
                _ => bail!(
                    "OIDC device authorization failed: {}{}",
                    error.error,
                    oauth_error_suffix(&error.error_description)
                ),
            }
        }
    }
}

impl RegistryClient {
    pub(crate) fn save_login(
        raw_url: &str,
        token: &str,
        workspace_id: Option<String>,
    ) -> Result<PathBuf> {
        let base_url = validate_registry_url(raw_url)?;
        validate_token(token)?;
        if let Some(workspace_id) = &workspace_id {
            validate_workspace_id(workspace_id)?;
        }
        let credentials = RegistryCredentials {
            url: base_url.as_str().trim_end_matches('/').to_string(),
            token: token.to_string(),
            workspace_id,
            refresh_token: None,
            expires_at: None,
            oidc: None,
        };
        save_credentials(&credentials)
    }

    pub(crate) fn start_oidc_device_login(
        raw_url: &str,
        workspace_id: Option<String>,
    ) -> Result<DeviceAuthorization> {
        let registry_url = validate_registry_url(raw_url)?;
        if let Some(workspace_id) = &workspace_id {
            validate_workspace_id(workspace_id)?;
        }
        let http = http_client()?;
        let config_url = registry_endpoint(&registry_url, None, &["auth", "config"])?;
        let response = http
            .get(config_url)
            .send()
            .context("cannot discover Registry OIDC configuration")?;
        if !response.status().is_success() {
            bail!(
                "Registry OIDC configuration discovery failed ({})",
                response.status()
            );
        }
        let config: OIDCClientConfig = decode_json_response(response, "Registry OIDC config")?;
        validate_oidc_client_config(&config)?;
        let oidc = OIDCCredentials {
            issuer: config.issuer,
            client_id: config.client_id,
            scope: config.scope,
            audience: config.audience.filter(|value| !value.is_empty()),
        };
        let discovery = discover_oidc(&http, &oidc.issuer)?;
        let endpoint = discovery
            .device_authorization_endpoint
            .context("OIDC provider does not advertise Device Authorization Grant support")?;
        let device_endpoint = validate_oidc_endpoint(&endpoint, "device authorization endpoint")?;
        let token_endpoint = validate_oidc_endpoint(&discovery.token_endpoint, "token endpoint")?;
        let mut form = vec![
            ("client_id", oidc.client_id.as_str()),
            ("scope", oidc.scope.as_str()),
        ];
        if let Some(audience) = &oidc.audience {
            form.push(("audience", audience.as_str()));
        }
        let response = http
            .post(device_endpoint)
            .form(&form)
            .send()
            .context("OIDC device authorization request failed")?;
        if !response.status().is_success() {
            let status = response.status();
            let detail = response_text_limited(response);
            bail!("OIDC device authorization request failed ({status}){detail}");
        }
        let authorization: DeviceAuthorizationResponse =
            decode_json_response(response, "OIDC device authorization")?;
        validate_device_authorization(&authorization)?;
        Ok(DeviceAuthorization {
            http,
            registry_url,
            workspace_id,
            oidc,
            token_endpoint,
            device_code: authorization.device_code,
            user_code: authorization.user_code,
            verification_uri: validate_interactive_url(
                &authorization.verification_uri,
                "verification URI",
            )?,
            verification_uri_complete: authorization
                .verification_uri_complete
                .as_deref()
                .map(|value| validate_interactive_url(value, "complete verification URI"))
                .transpose()?,
            deadline: Instant::now() + Duration::from_secs(authorization.expires_in),
            interval: Duration::from_secs(authorization.interval),
        })
    }

    pub(crate) fn load() -> Result<Self> {
        let path = credentials_path()?;
        let mut credentials = read_credentials(&path)?;
        let base_url = validate_registry_url(&credentials.url)
            .context("invalid Registry URL in credentials")?;
        validate_token(&credentials.token).context("invalid Registry token in credentials")?;
        if let Some(workspace_id) = &credentials.workspace_id {
            validate_workspace_id(workspace_id)
                .context("invalid workspace ID in Registry credentials")?;
        }
        let http = http_client()?;
        refresh_credentials_if_needed(&http, &mut credentials)?;
        Ok(Self {
            http,
            base_url,
            token: credentials.token,
            workspace_id: credentials.workspace_id,
        })
    }

    pub(crate) fn list_workspaces(&self) -> Result<Vec<RemoteWorkspace>> {
        let mut cursor: Option<String> = None;
        let mut workspaces = Vec::new();
        let mut seen_cursors = BTreeSet::new();
        for _ in 0..MAX_RELEASE_PAGES {
            let mut url = registry_endpoint(&self.base_url, None, &["workspaces"])?;
            {
                let mut query = url.query_pairs_mut();
                query.append_pair("limit", "200");
                if let Some(cursor) = &cursor {
                    query.append_pair("cursor", cursor);
                }
            }
            let response = self.http.get(url).bearer_auth(&self.token).send()?;
            if !response.status().is_success() {
                bail!("workspace listing failed ({})", response.status());
            }
            let page: RemoteWorkspacePage = decode_json_response(response, "workspace listing")?;
            if page.items.len() > 200 {
                bail!("workspace listing returned more than 200 items in one page");
            }
            for workspace in &page.items {
                validate_workspace_id(&workspace.id)?;
                validate_bounded_value(&workspace.slug, 128, "workspace slug")?;
                validate_bounded_value(&workspace.name, 512, "workspace name")?;
            }
            workspaces.extend(page.items);
            match page.next_cursor {
                Some(value) if !value.is_empty() => {
                    validate_bounded_value(&value, 2048, "workspace cursor")?;
                    if !seen_cursors.insert(value.clone()) {
                        bail!("workspace listing returned a repeated cursor");
                    }
                    cursor = Some(value);
                }
                _ => return Ok(workspaces),
            }
        }
        bail!("workspace listing exceeded {MAX_RELEASE_PAGES} pages")
    }

    pub(crate) fn select_workspace(workspace_id: &str) -> Result<PathBuf> {
        validate_workspace_id(workspace_id)?;
        let client = Self::load()?;
        if !client
            .list_workspaces()?
            .iter()
            .any(|workspace| workspace.id == workspace_id)
        {
            bail!("workspace is not visible to the current Registry principal");
        }
        let path = credentials_path()?;
        let mut credentials = read_credentials(&path)?;
        credentials.workspace_id = Some(workspace_id.to_string());
        save_credentials(&credentials)
    }

    pub(crate) fn logout() -> Result<PathBuf> {
        let path = credentials_path()?;
        let metadata = fs::symlink_metadata(&path).with_context(|| {
            format!(
                "not logged in; Registry credentials do not exist at {}",
                path.display()
            )
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            bail!(
                "Registry credentials path is not a regular file: {}",
                path.display()
            );
        }
        fs::remove_file(&path)?;
        Ok(path)
    }

    pub(crate) fn require_workspace(&self, command: &str) -> Result<&str> {
        self.workspace_id
            .as_deref()
            .with_context(|| format!("registry credentials require --workspace for {command}"))
    }

    pub(crate) fn reconcile_plan(&self, device: &str) -> Result<RemotePlan> {
        let response = self
            .http
            .get(self.endpoint(&["devices", device, "plan"])?)
            .bearer_auth(&self.token)
            .send()?;
        if !response.status().is_success() {
            bail!("reconcile plan failed ({})", response.status());
        }
        decode_json_response(response, "reconcile plan")
    }

    pub(crate) fn heartbeat(
        &self,
        device: &str,
        installed: &BTreeMap<String, String>,
    ) -> Result<()> {
        let response = self
            .http
            .post(self.endpoint(&["devices", device, "heartbeat"])?)
            .bearer_auth(&self.token)
            .json(&serde_json::json!({"agent":"agentx","installed_packages":installed}))
            .send()?;
        if !response.status().is_success() {
            bail!("heartbeat failed ({})", response.status());
        }
        Ok(())
    }

    pub(crate) fn download_artifact(&self, digest: &str) -> Result<Vec<u8>> {
        validate_sha256(digest, "artifact")?;
        let response = self
            .http
            .get(self.endpoint(&["artifacts", digest])?)
            .bearer_auth(&self.token)
            .send()?;
        if !response.status().is_success() {
            bail!("artifact download failed ({})", response.status());
        }
        let bytes = read_response_limited(response, MAX_ARTIFACT_BYTES, "artifact download")?;
        let actual = format!("{:x}", Sha256::digest(&bytes));
        if actual != digest {
            bail!("artifact hash mismatch: expected {digest}, got {actual}");
        }
        Ok(bytes)
    }

    pub(crate) fn fetch_team_manifest(&self) -> Result<TeamManifestDocument> {
        self.require_workspace("team commands")?;
        let response = self
            .http
            .get(self.endpoint(&["manifest"])?)
            .bearer_auth(&self.token)
            .send()?;
        if !response.status().is_success() {
            bail!("team manifest pull failed ({})", response.status());
        }
        let body: serde_json::Value = decode_json_response(response, "team manifest")?;
        match body.get("document").cloned() {
            Some(value)
                if body.get("revision").and_then(serde_json::Value::as_i64) == Some(0)
                    && value.as_object().is_some_and(serde_json::Map::is_empty) =>
            {
                Ok(TeamManifestDocument {
                    version: 1,
                    packages: Vec::new(),
                })
            }
            Some(value) => serde_json::from_value(value).context("invalid team manifest"),
            None => serde_json::from_value(body).context("invalid team manifest"),
        }
    }

    pub(crate) fn replace_team_manifest(&self, document: &TeamManifestDocument) -> Result<i64> {
        self.require_workspace("team commands")?;
        let response = self
            .http
            .put(self.endpoint(&["manifest"])?)
            .bearer_auth(&self.token)
            .json(&serde_json::json!({"document": document}))
            .send()?;
        if !response.status().is_success() {
            bail!("team manifest push failed ({})", response.status());
        }
        Ok(
            decode_json_response::<serde_json::Value>(response, "team manifest update")?
                .get("revision")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or_default(),
        )
    }

    pub(crate) fn publish(
        &self,
        name: &str,
        version: &str,
        file_name: &str,
        bytes: Vec<u8>,
        signature: Option<String>,
    ) -> Result<String> {
        let digest = format!("{:x}", Sha256::digest(&bytes));
        let mut form = multipart::Form::new()
            .text("version", version.to_string())
            .part(
                "artifact",
                multipart::Part::bytes(bytes).file_name(file_name.to_string()),
            );
        if let Some(signature) = signature {
            form = form.text("signature", signature);
        }
        let response = self
            .http
            .post(self.endpoint(&["packages", name, "releases"])?)
            .bearer_auth(&self.token)
            .header("Idempotency-Key", format!("{name}@{version}:{digest}"))
            .multipart(form)
            .send()?;
        if !response.status().is_success() {
            let status = response.status();
            let detail = response_text_limited(response);
            bail!("publish failed ({status}){detail}");
        }
        let release: RemoteRelease = decode_json_response(response, "publish")?;
        if release.name != name || release.version != version || release.sha256 != digest {
            bail!(
                "publish response mismatch: expected {}@{} {}, got {}@{} {}",
                name,
                version,
                digest,
                release.name,
                release.version,
                release.sha256
            );
        }
        Ok(digest)
    }

    pub(crate) fn pull(&self, name: &str, version: &str) -> Result<Vec<u8>> {
        let release = self
            .list_releases()?
            .into_iter()
            .find(|release| release.name == name && release.version == version)
            .context("release not found")?;
        validate_sha256(&release.sha256, "release")?;
        let bytes = self.download_artifact(&release.sha256)?;
        Ok(bytes)
    }

    fn list_releases(&self) -> Result<Vec<RemoteRelease>> {
        let mut cursor: Option<String> = None;
        let mut releases = Vec::new();
        let mut seen_cursors = BTreeSet::new();
        for _ in 0..MAX_RELEASE_PAGES {
            let mut url = self.endpoint(&["packages"])?;
            {
                let mut query = url.query_pairs_mut();
                query.append_pair("limit", "200");
                if let Some(cursor) = &cursor {
                    query.append_pair("cursor", cursor);
                }
            }
            let response = self.http.get(url).bearer_auth(&self.token).send()?;
            if !response.status().is_success() {
                bail!("package listing failed ({})", response.status());
            }
            match decode_json_response::<RemoteReleasePage>(response, "package listing")? {
                RemoteReleasePage::Legacy(items) => {
                    releases.extend(items);
                    return Ok(releases);
                }
                RemoteReleasePage::Paged { items, next_cursor } => {
                    if items.len() > 200 {
                        bail!("package listing returned more than 200 items in one page");
                    }
                    releases.extend(items);
                    match next_cursor {
                        Some(value) if !value.is_empty() => {
                            validate_bounded_value(&value, 2048, "package cursor")?;
                            if !seen_cursors.insert(value.clone()) {
                                bail!("package listing returned a repeated cursor");
                            }
                            cursor = Some(value);
                        }
                        _ => return Ok(releases),
                    }
                }
            }
        }
        bail!("package listing exceeded {MAX_RELEASE_PAGES} pages")
    }

    fn endpoint(&self, resource: &[&str]) -> Result<Url> {
        registry_endpoint(&self.base_url, self.workspace_id.as_deref(), resource)
    }
}

fn http_client() -> Result<Client> {
    Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(300))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("agentx-cli/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("cannot create Registry HTTP client")
}

fn registry_endpoint(base_url: &Url, workspace_id: Option<&str>, resource: &[&str]) -> Result<Url> {
    let mut url = base_url.clone();
    let mut segments = url
        .path_segments_mut()
        .map_err(|_| anyhow!("Registry URL cannot be a base URL"))?;
    segments.pop_if_empty().push("v1");
    if let Some(workspace_id) = workspace_id {
        segments.push("workspaces").push(workspace_id);
    }
    for segment in resource {
        segments.push(segment);
    }
    drop(segments);
    Ok(url)
}

fn save_credentials(credentials: &RegistryCredentials) -> Result<PathBuf> {
    let path = credentials_path()?;
    write_credentials(&path, &serde_json::to_vec_pretty(credentials)?)?;
    Ok(path)
}

fn read_credentials(path: &std::path::Path) -> Result<RegistryCredentials> {
    let metadata = fs::symlink_metadata(path).with_context(|| {
        format!(
            "not logged in; run `agentx registry login <url> --oidc` or provide a token ({})",
            path.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!(
            "Registry credentials path is not a regular file: {}",
            path.display()
        );
    }
    if metadata.len() > MAX_CREDENTIAL_BYTES {
        bail!("Registry credentials exceed {MAX_CREDENTIAL_BYTES} bytes");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        }
    }
    let raw = fs::read_to_string(path).context("invalid Registry credentials encoding")?;
    serde_json::from_str(&raw).context("invalid Registry credentials")
}

fn refresh_credentials_if_needed(
    http: &Client,
    credentials: &mut RegistryCredentials,
) -> Result<()> {
    let Some(expires_at) = credentials.expires_at else {
        return Ok(());
    };
    if expires_at > unix_time()?.saturating_add(60) {
        return Ok(());
    }
    let oidc = credentials
        .oidc
        .as_ref()
        .context("OIDC credentials are expired; run `agentx registry login --oidc` again")?;
    validate_stored_oidc(oidc)?;
    let refresh_token = credentials
        .refresh_token
        .as_deref()
        .context("OIDC refresh token is unavailable; run `agentx registry login --oidc` again")?;
    validate_token(refresh_token).context("invalid OIDC refresh token in credentials")?;
    let discovery = discover_oidc(http, &oidc.issuer)?;
    let token_endpoint = validate_oidc_endpoint(&discovery.token_endpoint, "token endpoint")?;
    let mut form = vec![
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", oidc.client_id.as_str()),
        ("scope", oidc.scope.as_str()),
    ];
    if let Some(audience) = &oidc.audience {
        form.push(("audience", audience.as_str()));
    }
    let response = http
        .post(token_endpoint)
        .form(&form)
        .send()
        .context("OIDC token refresh request failed")?;
    if !response.status().is_success() {
        let status = response.status();
        let detail = response_text_limited(response);
        bail!(
            "OIDC token refresh failed ({status}){detail}; run `agentx registry login --oidc` again"
        );
    }
    let token: OAuthTokenResponse = decode_json_response(response, "OIDC refresh token")?;
    validate_oauth_token(&token)?;
    credentials.token = token.access_token;
    if token.refresh_token.is_some() {
        credentials.refresh_token = token.refresh_token;
    }
    credentials.expires_at = Some(unix_time()?.saturating_add(token.expires_in));
    save_credentials(credentials)?;
    Ok(())
}

fn discover_oidc(http: &Client, raw_issuer: &str) -> Result<OIDCDiscovery> {
    let issuer = validate_oidc_base_url(raw_issuer, "OIDC issuer")?;
    let mut discovery_url = issuer.clone();
    {
        let mut segments = discovery_url
            .path_segments_mut()
            .map_err(|_| anyhow!("OIDC issuer cannot be a base URL"))?;
        segments
            .pop_if_empty()
            .push(".well-known")
            .push("openid-configuration");
    }
    let response = http
        .get(discovery_url)
        .send()
        .context("OIDC discovery request failed")?;
    if !response.status().is_success() {
        bail!("OIDC discovery failed ({})", response.status());
    }
    let discovery: OIDCDiscovery = decode_json_response(response, "OIDC discovery")?;
    let discovered_issuer = validate_oidc_base_url(&discovery.issuer, "discovered OIDC issuer")?;
    if normalize_url(&issuer) != normalize_url(&discovered_issuer) {
        bail!("OIDC discovery issuer does not match the configured issuer");
    }
    Ok(discovery)
}

fn validate_oidc_client_config(config: &OIDCClientConfig) -> Result<()> {
    validate_oidc_base_url(&config.issuer, "Registry OIDC issuer")?;
    validate_bounded_value(&config.client_id, 256, "OIDC client ID")?;
    validate_bounded_value(&config.scope, 1024, "OIDC scope")?;
    if let Some(audience) = &config.audience {
        if !audience.is_empty() {
            validate_bounded_value(audience, 512, "OIDC audience")?;
        }
    }
    Ok(())
}

fn validate_stored_oidc(oidc: &OIDCCredentials) -> Result<()> {
    validate_oidc_base_url(&oidc.issuer, "OIDC issuer in credentials")?;
    validate_bounded_value(&oidc.client_id, 256, "OIDC client ID in credentials")?;
    validate_bounded_value(&oidc.scope, 1024, "OIDC scope in credentials")?;
    if let Some(audience) = &oidc.audience {
        validate_bounded_value(audience, 512, "OIDC audience in credentials")?;
    }
    Ok(())
}

fn validate_device_authorization(response: &DeviceAuthorizationResponse) -> Result<()> {
    validate_bounded_value(&response.device_code, 8192, "OIDC device code")?;
    validate_bounded_value(&response.user_code, 256, "OIDC user code")?;
    if !(1..=3600).contains(&response.expires_in) {
        bail!("OIDC device authorization expiry must be between 1 and 3600 seconds");
    }
    if !(1..=30).contains(&response.interval) {
        bail!("OIDC device polling interval must be between 1 and 30 seconds");
    }
    Ok(())
}

fn validate_oauth_token(token: &OAuthTokenResponse) -> Result<()> {
    validate_token(&token.access_token).context("invalid OIDC access token")?;
    if !token.token_type.eq_ignore_ascii_case("bearer") {
        bail!("OIDC token endpoint returned a non-bearer token");
    }
    if !(1..=86_400).contains(&token.expires_in) {
        bail!("OIDC access token expiry must be between 1 and 86400 seconds");
    }
    if let Some(refresh_token) = &token.refresh_token {
        validate_token(refresh_token).context("invalid OIDC refresh token")?;
    }
    Ok(())
}

fn validate_bounded_value(value: &str, maximum: usize, label: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > maximum
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        bail!("{label} must be non-empty, bounded, and contain no padding or control characters");
    }
    Ok(())
}

fn validate_oidc_base_url(raw: &str, label: &str) -> Result<Url> {
    let url = Url::parse(raw).with_context(|| format!("{label} must be an absolute URL"))?;
    validate_secure_url(&url, label, false)?;
    Ok(url)
}

fn validate_oidc_endpoint(raw: &str, label: &str) -> Result<Url> {
    let url = Url::parse(raw).with_context(|| format!("OIDC {label} must be an absolute URL"))?;
    validate_secure_url(&url, &format!("OIDC {label}"), true)?;
    Ok(url)
}

fn validate_interactive_url(raw: &str, label: &str) -> Result<Url> {
    let url = Url::parse(raw).with_context(|| format!("OIDC {label} must be an absolute URL"))?;
    validate_secure_url(&url, &format!("OIDC {label}"), true)?;
    Ok(url)
}

fn validate_secure_url(url: &Url, label: &str, allow_query: bool) -> Result<()> {
    if url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || (!allow_query && url.query().is_some())
    {
        bail!("{label} contains unsupported URL components");
    }
    if url.scheme() != "https" && !(url.scheme() == "http" && is_loopback(url)) {
        bail!("{label} must use HTTPS, except for loopback development servers");
    }
    Ok(())
}

fn is_loopback(url: &Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    host.eq_ignore_ascii_case("localhost")
        || host
            .trim_matches(['[', ']'])
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn normalize_url(url: &Url) -> String {
    url.as_str().trim_end_matches('/').to_string()
}

fn decode_json_response<T: DeserializeOwned>(response: Response, label: &str) -> Result<T> {
    let bytes = read_response_limited(response, MAX_JSON_RESPONSE_BYTES, label)?;
    serde_json::from_slice(&bytes).with_context(|| format!("invalid {label} response"))
}

fn read_response_limited(mut response: Response, maximum: usize, label: &str) -> Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > maximum as u64)
    {
        bail!("{label} response exceeds {maximum} bytes");
    }
    let mut bytes = Vec::new();
    response
        .by_ref()
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        bail!("{label} response exceeds {maximum} bytes");
    }
    Ok(bytes)
}

fn response_text_limited(response: Response) -> String {
    let Ok(bytes) = read_response_limited(response, MAX_ERROR_RESPONSE_BYTES, "error") else {
        return String::new();
    };
    let text = String::from_utf8_lossy(&bytes);
    let clean = sanitize_error_detail(&text);
    if clean.is_empty() {
        String::new()
    } else {
        format!(": {clean}")
    }
}

fn oauth_error_suffix(description: &str) -> String {
    let clean = sanitize_error_detail(description);
    if clean.is_empty() {
        String::new()
    } else {
        format!(": {clean}")
    }
}

fn sanitize_error_detail(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .take(MAX_ERROR_DISPLAY_CHARS)
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn unix_time() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn default_device_poll_interval() -> u64 {
    5
}

fn credentials_path() -> Result<PathBuf> {
    let dirs = BaseDirs::new().context("cannot find home directory")?;
    Ok(dirs.config_dir().join("agentx/credentials.json"))
}

fn validate_registry_url(raw: &str) -> Result<Url> {
    let url = Url::parse(raw).context("Registry URL must be an absolute URL")?;
    validate_secure_url(&url, "Registry URL", false)?;
    Ok(url)
}

fn validate_token(token: &str) -> Result<()> {
    if token.is_empty()
        || token.len() > 8192
        || token.trim() != token
        || token.chars().any(char::is_control)
    {
        bail!(
            "Registry token must be non-empty, bounded, and contain no whitespace padding or control characters"
        );
    }
    Ok(())
}

fn write_credentials(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("credentials path has no parent")?;
    fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(
        ".credentials-{}.tmp",
        crate::infrastructure::filesystem::operation_nonce()?
    ));
    let result = (|| -> Result<()> {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temporary)
            .with_context(|| format!("cannot create {}", temporary.display()))?;
        use std::io::Write;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_url_rejects_insecure_remote_and_embedded_credentials() {
        assert!(validate_registry_url("https://registry.example.com/base").is_ok());
        assert!(validate_registry_url("http://127.0.0.1:8080").is_ok());
        assert!(validate_registry_url("http://registry.example.com").is_err());
        assert!(validate_registry_url("https://user:pass@registry.example.com").is_err());
        assert!(validate_registry_url("https://registry.example.com?token=secret").is_err());
    }

    #[test]
    fn token_validation_rejects_empty_padded_and_control_values() {
        assert!(validate_token("opaque-token").is_ok());
        assert!(validate_token("").is_err());
        assert!(validate_token(" token").is_err());
        assert!(validate_token("token\nvalue").is_err());
    }

    #[test]
    fn oauth_error_details_are_bounded_and_single_line() {
        let detail = format!(
            "provider\n\x1b[31m{}",
            "x".repeat(MAX_ERROR_DISPLAY_CHARS + 20)
        );
        let clean = sanitize_error_detail(&detail);
        assert!(!clean.contains('\n'));
        assert!(!clean.contains('\x1b'));
        assert!(clean.chars().count() <= MAX_ERROR_DISPLAY_CHARS);
    }
}
