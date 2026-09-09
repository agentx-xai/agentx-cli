use flate2::{Compression, write::GzEncoder};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    process::{Command, Stdio},
    thread::{self, JoinHandle},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tar::{Builder, Header};

fn temp_dir(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "agentx-{name}-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&p).unwrap();
    p
}
fn server(responses: Vec<(String, Option<String>, Vec<u8>)>) -> (String, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
        for (expected, body_contains, body) in responses {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let request = read_request(&mut stream);
            assert!(
                request.starts_with(&expected),
                "unexpected request: {request}"
            );
            assert!(
                request
                    .to_ascii_lowercase()
                    .contains("authorization: bearer token"),
                "missing bearer token: {request}"
            );
            if let Some(fragment) = body_contains {
                assert!(request.contains(&fragment), "unexpected body: {request}");
            }
            let status = if expected.contains("/heartbeat") {
                "204 No Content"
            } else if expected.starts_with("POST") {
                "201 Created"
            } else {
                "200 OK"
            };
            let reply = format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\nContent-Type: application/json\r\n\r\n{}",
                body.len(),
                ""
            );
            stream.write_all(reply.as_bytes()).unwrap();
            let _ = stream.write_all(&body);
        }
    });
    (format!("http://{}", addr), handle)
}

fn public_server<F>(build: F) -> (String, JoinHandle<()>)
where
    F: FnOnce(&str) -> Vec<(String, String, Vec<u8>)>,
{
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let responses = build(&base);
    let handle = thread::spawn(move || {
        for (expected, status, body) in responses {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let request = read_request(&mut stream);
            assert!(
                request.starts_with(&expected),
                "unexpected request: {request}"
            );
            assert!(
                !request.to_ascii_lowercase().contains("authorization:"),
                "unexpected authorization: {request}"
            );
            write_response(&mut stream, &status, &body);
        }
    });
    (base, handle)
}

fn oversized_artifact_server(digest: &str) -> (String, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let digest = digest.to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = read_request(&mut stream);
        assert!(
            request.starts_with("GET /v1/packages"),
            "unexpected request: {request}"
        );
        let body = format!("[{{\"name\":\"demo\",\"version\":\"1.0.0\",\"sha256\":\"{digest}\"}}]");
        write_response(&mut stream, "200 OK", body.as_bytes());

        let (mut stream, _) = listener.accept().unwrap();
        let request = read_request(&mut stream);
        assert!(
            request.starts_with(&format!("GET /v1/artifacts/{digest}")),
            "unexpected request: {request}"
        );
        let declared_size = (51usize << 20) + 1;
        let headers = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {declared_size}\r\nConnection: close\r\nContent-Type: application/gzip\r\n\r\n"
        );
        stream.write_all(headers.as_bytes()).unwrap();
    });
    (base, handle)
}
fn read_request(stream: &mut TcpStream) -> String {
    let mut data = Vec::new();
    let mut buf = [0u8; 4096];
    let mut content_len = 0usize;
    loop {
        let n = stream.read(&mut buf).unwrap();
        if n == 0 {
            break;
        };
        data.extend_from_slice(&buf[..n]);
        if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
            let headers = String::from_utf8_lossy(&data[..pos]);
            for line in headers.lines() {
                if let Some(v) = line.strip_prefix("Content-Length:") {
                    content_len = v.trim().parse().unwrap_or(0)
                }
            }
            if data.len() >= pos + 4 + content_len {
                break;
            }
        }
    }
    String::from_utf8_lossy(&data).into_owned()
}
fn run(home: &PathBuf, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_agentx"))
        .args(args)
        .env("HOME", home)
        .env_remove("XDG_CONFIG_HOME")
        .current_dir(home)
        .output()
        .unwrap()
}

fn run_with_stdin(home: &PathBuf, args: &[&str], stdin: &str) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_agentx"))
        .args(args)
        .env("HOME", home)
        .env_remove("XDG_CONFIG_HOME")
        .current_dir(home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn write_response(stream: &mut TcpStream, status: &str, body: &[u8]) {
    let headers = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\nContent-Type: application/json\r\n\r\n",
        body.len()
    );
    stream.write_all(headers.as_bytes()).unwrap();
    stream.write_all(body).unwrap();
}

fn oidc_server() -> (String, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let server_base = base.clone();
    let handle = thread::spawn(move || {
        let steps = vec![
            (
                "GET /v1/auth/config",
                None,
                None,
                format!(
                    "{{\"issuer\":\"{server_base}\",\"client_id\":\"agentx-cli\",\"audience\":\"agentx\",\"scope\":\"openid profile offline_access\"}}"
                ),
            ),
            (
                "GET /.well-known/openid-configuration",
                None,
                None,
                format!(
                    "{{\"issuer\":\"{server_base}\",\"token_endpoint\":\"{server_base}/token\",\"device_authorization_endpoint\":\"{server_base}/device/code\"}}"
                ),
            ),
            (
                "POST /device/code",
                None,
                Some("client_id=agentx-cli"),
                format!(
                    "{{\"device_code\":\"device-secret\",\"user_code\":\"ABCD-EFGH\",\"verification_uri\":\"{server_base}/device\",\"verification_uri_complete\":\"{server_base}/device?user_code=ABCD-EFGH\",\"expires_in\":60,\"interval\":1}}"
                ),
            ),
            (
                "POST /token",
                None,
                Some("device_code=device-secret"),
                "{\"access_token\":\"first-access-token\",\"token_type\":\"Bearer\",\"expires_in\":1,\"refresh_token\":\"first-refresh-token\"}".into(),
            ),
            (
                "GET /.well-known/openid-configuration",
                None,
                None,
                format!(
                    "{{\"issuer\":\"{server_base}\",\"token_endpoint\":\"{server_base}/token\"}}"
                ),
            ),
            (
                "POST /token",
                None,
                Some("refresh_token=first-refresh-token"),
                "{\"access_token\":\"refreshed-access-token\",\"token_type\":\"Bearer\",\"expires_in\":3600,\"refresh_token\":\"rotated-refresh-token\"}".into(),
            ),
            (
                "GET /v1/workspaces/workspace-1/manifest",
                Some("authorization: bearer refreshed-access-token"),
                None,
                "{\"revision\":0,\"document\":{}}".into(),
            ),
        ];
        for (expected, authorization, body_fragment, response) in steps {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let request = read_request(&mut stream);
            assert!(
                request.starts_with(expected),
                "unexpected request: {request}"
            );
            if let Some(authorization) = authorization {
                assert!(
                    request.to_ascii_lowercase().contains(authorization),
                    "missing authorization: {request}"
                );
            } else {
                assert!(
                    !request.to_ascii_lowercase().contains("authorization:"),
                    "unexpected authorization: {request}"
                );
            }
            if let Some(fragment) = body_fragment {
                assert!(request.contains(fragment), "unexpected body: {request}");
            }
            write_response(&mut stream, "200 OK", response.as_bytes());
        }
    });
    (base, handle)
}

fn find_file(root: &PathBuf, name: &str) -> Option<PathBuf> {
    for entry in fs::read_dir(root).ok()? {
        let path = entry.ok()?.path();
        if path.is_dir() {
            if let Some(found) = find_file(&path, name) {
                return Some(found);
            }
        } else if path.file_name().and_then(|value| value.to_str()) == Some(name) {
            return Some(path);
        }
    }
    None
}

fn skill_archive() -> Vec<u8> {
    skill_archive_with_body(b"# Signed package\n")
}

fn skill_archive_with_body(body: &[u8]) -> Vec<u8> {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut archive = Builder::new(encoder);
    let mut header = Header::new_gnu();
    header.set_size(body.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    archive.append_data(&mut header, "SKILL.md", body).unwrap();
    archive.into_inner().unwrap().finish().unwrap()
}

#[test]
fn registry_login_publish_and_pull_round_trip() {
    let home = temp_dir("registry-home");
    let artifact = temp_dir("registry-artifact").join("skill.tar.gz");
    let bytes = skill_archive();
    fs::write(&artifact, &bytes).unwrap();
    let digest = format!("{:x}", Sha256::digest(&bytes));
    let (publish_url, publish_server) = server(vec![(
        "POST /v1/packages/demo/releases".into(),
        None,
        format!(
            "{{\"name\":\"demo\",\"version\":\"1.0.0\",\"sha256\":\"{}\"}}",
            digest
        )
        .into_bytes(),
    )]);
    let login = run(
        &home,
        ["registry", "login", &publish_url, "--token", "token"].as_slice(),
    );
    assert!(
        login.status.success(),
        "{}",
        String::from_utf8_lossy(&login.stderr)
    );
    let credentials = find_file(&home, "credentials.json").expect("credentials file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(credentials).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let publish = run(
        &home,
        [
            "registry",
            "publish",
            "demo",
            "1.0.0",
            artifact.to_str().unwrap(),
        ]
        .as_slice(),
    );
    assert!(
        publish.status.success(),
        "{}",
        String::from_utf8_lossy(&publish.stderr)
    );
    publish_server.join().unwrap();
    let (pull_url, pull_server) = server(vec![
        (
            "GET /v1/packages".into(),
            None,
            format!(
                "[{{\"name\":\"demo\",\"version\":\"1.0.0\",\"sha256\":\"{}\"}}]",
                digest
            )
            .into_bytes(),
        ),
        (format!("GET /v1/artifacts/{digest}"), None, bytes.clone()),
    ]);
    let login = run(
        &home,
        ["registry", "login", &pull_url, "--token", "token"].as_slice(),
    );
    assert!(login.status.success());
    let output = temp_dir("registry-output").join("skill.tar");
    let pull = run(
        &home,
        [
            "registry",
            "pull",
            "demo",
            "1.0.0",
            "--output",
            output.to_str().unwrap(),
        ]
        .as_slice(),
    );
    assert!(
        pull.status.success(),
        "{}",
        String::from_utf8_lossy(&pull.stderr)
    );
    assert_eq!(fs::read(output).unwrap(), bytes);
    pull_server.join().unwrap();
}

#[test]
fn registry_login_accepts_token_from_stdin() {
    let home = temp_dir("registry-stdin-home");
    let login = run_with_stdin(
        &home,
        ["registry", "login", "http://127.0.0.1:9", "--token-stdin"].as_slice(),
        "stdin-token\n",
    );
    assert!(
        login.status.success(),
        "{}",
        String::from_utf8_lossy(&login.stderr)
    );
    let credentials = find_file(&home, "credentials.json").expect("credentials file");
    let value: serde_json::Value = serde_json::from_slice(&fs::read(credentials).unwrap()).unwrap();
    assert_eq!(value["token"], "stdin-token");
    fs::remove_dir_all(home).unwrap();
}

#[test]
fn registry_workspace_selection_and_logout_complete_session_lifecycle() {
    let home = temp_dir("registry-session-home");
    let workspace = "123e4567-e89b-12d3-a456-426614174000";
    let page = format!(
        "{{\"items\":[{{\"id\":\"{workspace}\",\"slug\":\"platform\",\"name\":\"Platform Team\"}}],\"count\":1}}"
    )
    .into_bytes();
    let (url, mock_server) = server(vec![
        ("GET /v1/workspaces".into(), None, page.clone()),
        ("GET /v1/workspaces".into(), None, page),
    ]);
    let login = run(
        &home,
        ["registry", "login", &url, "--token", "token"].as_slice(),
    );
    assert!(login.status.success());

    let list = run(&home, ["registry", "workspaces"].as_slice());
    assert!(list.status.success());
    let output = String::from_utf8_lossy(&list.stdout);
    assert!(output.contains(workspace));
    assert!(output.contains("platform"));

    let select = run(&home, ["registry", "use", workspace].as_slice());
    assert!(
        select.status.success(),
        "{}",
        String::from_utf8_lossy(&select.stderr)
    );
    mock_server.join().unwrap();
    let credentials = find_file(&home, "credentials.json").expect("credentials file");
    let value: serde_json::Value =
        serde_json::from_slice(&fs::read(&credentials).unwrap()).unwrap();
    assert_eq!(value["workspace_id"], workspace);

    let logout = run(&home, ["registry", "logout"].as_slice());
    assert!(logout.status.success());
    assert!(!credentials.exists());
    fs::remove_dir_all(home).unwrap();
}

#[cfg(unix)]
#[test]
fn registry_rejects_symlinked_credentials_before_network_access() {
    use std::os::unix::fs::symlink;

    let home = temp_dir("registry-symlink-credentials-home");
    let login = run(
        &home,
        [
            "registry",
            "login",
            "http://127.0.0.1:9",
            "--token",
            "token",
        ]
        .as_slice(),
    );
    assert!(login.status.success());
    let credentials = find_file(&home, "credentials.json").expect("credentials file");
    let target = home.join("attacker-controlled.json");
    fs::write(&target, r#"{"url":"http://127.0.0.1:9","token":"stolen"}"#).unwrap();
    fs::remove_file(&credentials).unwrap();
    symlink(&target, &credentials).unwrap();

    let list = run(&home, ["registry", "workspaces"].as_slice());
    assert!(!list.status.success());
    assert!(String::from_utf8_lossy(&list.stderr).contains("not a regular file"));
    fs::remove_dir_all(home).unwrap();
}

#[test]
fn oidc_device_login_refreshes_before_registry_use() {
    let home = temp_dir("registry-oidc-home");
    let (url, mock_server) = oidc_server();
    let login = run(
        &home,
        [
            "registry",
            "login",
            &url,
            "--oidc",
            "--workspace",
            "workspace-1",
        ]
        .as_slice(),
    );
    assert!(
        login.status.success(),
        "{}",
        String::from_utf8_lossy(&login.stderr)
    );
    let output = String::from_utf8_lossy(&login.stdout);
    assert!(output.contains("/device?user_code=ABCD-EFGH"));
    assert!(output.contains("Confirm code: ABCD-EFGH"));

    let pull = run(&home, ["team", "pull"].as_slice());
    assert!(
        pull.status.success(),
        "{}",
        String::from_utf8_lossy(&pull.stderr)
    );
    mock_server.join().unwrap();
    let credentials = find_file(&home, "credentials.json").expect("credentials file");
    let value: serde_json::Value = serde_json::from_slice(&fs::read(credentials).unwrap()).unwrap();
    assert_eq!(value["token"], "refreshed-access-token");
    assert_eq!(value["refresh_token"], "rotated-refresh-token");
    assert_eq!(value["oidc"]["client_id"], "agentx-cli");
    assert!(home.join("agentx.team.yaml").is_file());
    fs::remove_dir_all(home).unwrap();
}

#[test]
fn oidc_discovery_rejects_issuer_mismatch_and_insecure_endpoint() {
    for insecure_endpoint in [false, true] {
        let home = temp_dir("registry-oidc-discovery-home");
        let (url, mock_server) = public_server(|base| {
            let discovery = if insecure_endpoint {
                format!(
                    "{{\"issuer\":\"{base}\",\"token_endpoint\":\"http://registry.example.com/token\",\"device_authorization_endpoint\":\"{base}/device/code\"}}"
                )
            } else {
                format!(
                    "{{\"issuer\":\"{base}/different\",\"token_endpoint\":\"{base}/token\",\"device_authorization_endpoint\":\"{base}/device/code\"}}"
                )
            };
            vec![
                (
                    "GET /v1/auth/config".into(),
                    "200 OK".into(),
                    format!(
                        "{{\"issuer\":\"{base}\",\"client_id\":\"agentx-cli\",\"scope\":\"openid offline_access\"}}"
                    )
                    .into_bytes(),
                ),
                (
                    "GET /.well-known/openid-configuration".into(),
                    "200 OK".into(),
                    discovery.into_bytes(),
                ),
            ]
        });
        let login = run(&home, ["registry", "login", &url, "--oidc"].as_slice());
        assert!(!login.status.success());
        let error = String::from_utf8_lossy(&login.stderr);
        if insecure_endpoint {
            assert!(error.contains("token endpoint must use HTTPS"), "{error}");
        } else {
            assert!(error.contains("issuer does not match"), "{error}");
        }
        mock_server.join().unwrap();
        assert!(find_file(&home, "credentials.json").is_none());
        fs::remove_dir_all(home).unwrap();
    }
}

#[test]
fn failed_oidc_refresh_requires_a_new_login() {
    let home = temp_dir("registry-oidc-refresh-failure-home");
    let (url, mock_server) = public_server(|base| {
        vec![
            (
                "GET /.well-known/openid-configuration".into(),
                "200 OK".into(),
                format!("{{\"issuer\":\"{base}\",\"token_endpoint\":\"{base}/token\"}}")
                    .into_bytes(),
            ),
            (
                "POST /token".into(),
                "400 Bad Request".into(),
                b"{\"error\":\"invalid_grant\",\"error_description\":\"expired\\nrefresh token\"}"
                    .to_vec(),
            ),
        ]
    });
    let login = run(
        &home,
        ["registry", "login", &url, "--token", "temporary-token"].as_slice(),
    );
    assert!(login.status.success());
    let credentials = find_file(&home, "credentials.json").expect("credentials file");
    fs::write(
        &credentials,
        format!(
            "{{\"url\":\"{url}\",\"token\":\"expired-access-token\",\"refresh_token\":\"expired-refresh-token\",\"expires_at\":1,\"oidc\":{{\"issuer\":\"{url}\",\"client_id\":\"agentx-cli\",\"scope\":\"openid offline_access\"}}}}"
        ),
    )
    .unwrap();

    let list = run(&home, ["registry", "workspaces"].as_slice());
    assert!(!list.status.success());
    let error = String::from_utf8_lossy(&list.stderr);
    assert!(
        error.contains("run `agentx registry login --oidc` again"),
        "{error}"
    );
    assert!(
        !error.contains('\n') || error.lines().count() <= 2,
        "{error}"
    );
    mock_server.join().unwrap();
    fs::remove_dir_all(home).unwrap();
}

#[test]
fn registry_rejects_insecure_login_and_unsafe_local_identifiers() {
    let home = temp_dir("registry-validation-home");
    let insecure = run(
        &home,
        [
            "registry",
            "login",
            "http://registry.example.com",
            "--token",
            "token",
        ]
        .as_slice(),
    );
    assert!(!insecure.status.success());
    assert!(String::from_utf8_lossy(&insecure.stderr).contains("must use HTTPS"));
    assert!(find_file(&home, "credentials.json").is_none());

    let unsafe_workspace = run(
        &home,
        [
            "registry",
            "login",
            "http://127.0.0.1:9",
            "--token",
            "token",
            "--workspace",
            "../escape",
        ]
        .as_slice(),
    );
    assert!(!unsafe_workspace.status.success());
    assert!(String::from_utf8_lossy(&unsafe_workspace.stderr).contains("unsafe workspace ID"));

    let login = run(
        &home,
        [
            "registry",
            "login",
            "http://127.0.0.1:9",
            "--token",
            "token",
            "--workspace",
            "workspace-1",
        ]
        .as_slice(),
    );
    assert!(login.status.success());
    let unsafe_device = run(&home, ["agent", "plan", "--device", "../escape"].as_slice());
    assert!(!unsafe_device.status.success());
    assert!(String::from_utf8_lossy(&unsafe_device.stderr).contains("unsafe device name"));
    assert!(!home.join(".agentx").exists());
    fs::remove_dir_all(home).unwrap();
}

#[test]
fn registry_pull_rejects_artifact_hash_mismatch_before_writing_output() {
    let home = temp_dir("registry-mismatch-home");
    let claimed = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let artifact = skill_archive();
    let (url, mock_server) = server(vec![
        (
            "GET /v1/packages".into(),
            None,
            format!("[{{\"name\":\"demo\",\"version\":\"1.0.0\",\"sha256\":\"{claimed}\"}}]")
                .into_bytes(),
        ),
        (format!("GET /v1/artifacts/{claimed}"), None, artifact),
    ]);
    let login = run(
        &home,
        ["registry", "login", &url, "--token", "token"].as_slice(),
    );
    assert!(login.status.success());

    let output = home.join("downloaded.tar.gz");
    let pull = run(
        &home,
        [
            "registry",
            "pull",
            "demo",
            "1.0.0",
            "--output",
            output.to_str().unwrap(),
        ]
        .as_slice(),
    );
    assert!(!pull.status.success());
    assert!(String::from_utf8_lossy(&pull.stderr).contains("artifact hash mismatch"));
    assert!(!output.exists());
    mock_server.join().unwrap();
    fs::remove_dir_all(home).unwrap();
}

#[test]
fn registry_rejects_oversized_json_and_artifact_responses() {
    let home = temp_dir("registry-response-limits-home");
    let (url, json_server) = server(vec![(
        "GET /v1/workspaces".into(),
        None,
        vec![b'x'; (2usize << 20) + 1],
    )]);
    let login = run(
        &home,
        ["registry", "login", &url, "--token", "token"].as_slice(),
    );
    assert!(login.status.success());
    let list = run(&home, ["registry", "workspaces"].as_slice());
    assert!(!list.status.success());
    assert!(String::from_utf8_lossy(&list.stderr).contains("response exceeds 2097152 bytes"));
    json_server.join().unwrap();

    let digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let (url, artifact_server) = oversized_artifact_server(digest);
    let login = run(
        &home,
        ["registry", "login", &url, "--token", "token"].as_slice(),
    );
    assert!(login.status.success());
    let output = home.join("oversized.tar.gz");
    let pull = run(
        &home,
        [
            "registry",
            "pull",
            "demo",
            "1.0.0",
            "--output",
            output.to_str().unwrap(),
        ]
        .as_slice(),
    );
    assert!(!pull.status.success());
    assert!(String::from_utf8_lossy(&pull.stderr).contains("response exceeds 53477376 bytes"));
    assert!(!output.exists());
    artifact_server.join().unwrap();
    fs::remove_dir_all(home).unwrap();
}

#[test]
fn team_manifest_uses_dedicated_validated_contract() {
    let home = temp_dir("team-home");
    let workspace = "workspace-1";
    let digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let get_path = format!("GET /v1/workspaces/{workspace}/manifest");
    let put_path = format!("PUT /v1/workspaces/{workspace}/manifest");
    let (url, mock_server) = server(vec![
        (
            get_path,
            None,
            format!(
                "{{\"revision\":2,\"document\":{{\"version\":1,\"packages\":[{{\"name\":\"demo\",\"version\":\"1.2.3\",\"sha256\":\"{digest}\"}}]}}}}"
            )
            .into_bytes(),
        ),
        (put_path, Some("\"version\":1".into()), br#"{"revision":3}"#.to_vec()),
    ]);
    let login = run(
        &home,
        [
            "registry",
            "login",
            &url,
            "--token",
            "token",
            "--workspace",
            workspace,
        ]
        .as_slice(),
    );
    assert!(login.status.success());
    let pull = run(&home, ["team", "pull"].as_slice());
    assert!(
        pull.status.success(),
        "{}",
        String::from_utf8_lossy(&pull.stderr)
    );
    let path = home.join("agentx.team.yaml");
    let pulled = fs::read_to_string(&path).unwrap();
    assert!(pulled.contains("version: 1"));
    assert!(pulled.contains("name: demo"));
    assert!(!home.join("agentx.yaml").exists());
    let push = run(&home, ["team", "push"].as_slice());
    assert!(
        push.status.success(),
        "{}",
        String::from_utf8_lossy(&push.stderr)
    );
    mock_server.join().unwrap();

    fs::write(
        &path,
        "version: 1\nskills:\n  - name: local\n    source: { type: local, path: skills/local }\n",
    )
    .unwrap();
    let invalid = run(&home, ["team", "push"].as_slice());
    assert!(!invalid.status.success());
    assert!(String::from_utf8_lossy(&invalid.stderr).contains("invalid team manifest YAML"));
    fs::remove_dir_all(home).unwrap();
}

#[test]
fn agent_sync_installs_from_http_and_rollback_restores_files() {
    let home = temp_dir("agent-http-home");
    let device = "device-1";
    let workspace = "workspace-1";
    let old_digest = "old-digest";
    let skill_root = home.join(".codex/skills/demo");
    fs::create_dir_all(&skill_root).unwrap();
    fs::write(skill_root.join("SKILL.md"), "# Old\n").unwrap();

    let state_dir = home.join(format!(".agentx/devices/{device}"));
    fs::create_dir_all(&state_dir).unwrap();
    fs::write(
        state_dir.join("state.json"),
        format!(
            "{{\"manifest_revision\":1,\"installed_packages\":{{\"demo\":\"{old_digest}\"}},\"target\":\"codex\",\"changed_packages\":[]}}"
        ),
    )
    .unwrap();

    let artifact = skill_archive_with_body(b"# New\n");
    let digest = format!("{:x}", Sha256::digest(&artifact));
    let plan = format!(
        "{{\"actions\":[{{\"package\":\"demo\",\"kind\":\"update\",\"from\":\"{old_digest}\",\"to\":\"{digest}\"}}],\"manifest_revision\":2}}"
    );
    let plan_path = format!("/v1/workspaces/{workspace}/devices/{device}/plan");
    let heartbeat_path = format!("/v1/workspaces/{workspace}/devices/{device}/heartbeat");
    let (url, mock_server) = server(vec![
        (format!("GET {plan_path}"), None, plan.into_bytes()),
        (
            format!("GET /v1/workspaces/{workspace}/artifacts/{digest}"),
            None,
            artifact,
        ),
        (
            format!("POST {heartbeat_path}"),
            Some(format!("\"demo\":\"{digest}\"")),
            Vec::new(),
        ),
        (
            format!("POST {heartbeat_path}"),
            Some(format!("\"demo\":\"{old_digest}\"")),
            Vec::new(),
        ),
    ]);
    let login = run(
        &home,
        [
            "registry",
            "login",
            &url,
            "--token",
            "token",
            "--workspace",
            workspace,
        ]
        .as_slice(),
    );
    assert!(login.status.success());

    let sync = run(
        &home,
        ["agent", "sync", "--device", device, "--target", "codex"].as_slice(),
    );
    assert!(
        sync.status.success(),
        "{}",
        String::from_utf8_lossy(&sync.stderr)
    );
    assert_eq!(
        fs::read_to_string(skill_root.join("SKILL.md")).unwrap(),
        "# New\n"
    );
    let synced_state: serde_json::Value =
        serde_json::from_slice(&fs::read(state_dir.join("state.json")).unwrap()).unwrap();
    assert_eq!(synced_state["manifest_revision"], 2);
    assert_eq!(synced_state["installed_packages"]["demo"], digest);

    let rollback = run(
        &home,
        ["agent", "rollback", "--device", device, "--target", "codex"].as_slice(),
    );
    assert!(
        rollback.status.success(),
        "{}",
        String::from_utf8_lossy(&rollback.stderr)
    );
    assert_eq!(
        fs::read_to_string(skill_root.join("SKILL.md")).unwrap(),
        "# Old\n"
    );
    let rolled_back_state: serde_json::Value =
        serde_json::from_slice(&fs::read(state_dir.join("state.json")).unwrap()).unwrap();
    assert_eq!(rolled_back_state["manifest_revision"], 1);
    assert_eq!(rolled_back_state["installed_packages"]["demo"], old_digest);
    mock_server.join().unwrap();
}
