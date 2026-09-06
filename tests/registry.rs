use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    process::Command,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

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
fn server(responses: Vec<(String, String)>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for (expected, body) in responses {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let request = read_request(&mut stream);
            assert!(
                request.starts_with(&expected),
                "unexpected request: {request}"
            );
            let status = if expected.starts_with("POST") {
                "201 Created"
            } else {
                "200 OK"
            };
            let reply = format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\nContent-Type: application/json\r\n\r\n{}",
                body.as_bytes().len(),
                body
            );
            stream.write_all(reply.as_bytes()).unwrap();
        }
    });
    format!("http://{}", addr)
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
        .output()
        .unwrap()
}

#[test]
fn registry_login_publish_and_pull_round_trip() {
    let home = temp_dir("registry-home");
    let artifact = temp_dir("registry-artifact").join("skill.tar");
    let bytes = b"signed-package";
    fs::write(&artifact, bytes).unwrap();
    let digest = format!("{:x}", Sha256::digest(bytes));
    let publish_url = server(vec![(
        "POST /v1/packages/demo/releases".into(),
        format!(
            "{{\"name\":\"demo\",\"version\":\"1.0.0\",\"sha256\":\"{}\"}}",
            digest
        ),
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
    let pull_url = server(vec![
        (
            "GET /v1/packages".into(),
            format!(
                "[{{\"name\":\"demo\",\"version\":\"1.0.0\",\"sha256\":\"{}\"}}]",
                digest
            ),
        ),
        (
            format!("GET /v1/artifacts/{digest}"),
            String::from_utf8(bytes.to_vec()).unwrap(),
        ),
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
}
