use assert_cmd::Command;
use predicates::prelude::*;
use std::thread;
use std::time::Duration;
use iris::server::IrisServer;
use iris::resolvers::build_resolver;

#[test]
fn test_cli_help_message() {
    let mut cmd = Command::cargo_bin("iris-cli").unwrap();

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("🌈 IrisDNS CLI"))
        .stdout(predicate::str::contains("Usage:"));
}

#[test]
fn test_cli_full_cycle_against_server() {
    // Setup real server in background
    let server_addr = "127.0.0.1:0";
    let resolver = build_resolver(None); // Local resolver
    let server = IrisServer::new(server_addr, resolver).unwrap();
    let local_socket_addr = server.get_local_addr().unwrap();
    let local_addr_str = local_socket_addr.to_string();

    thread::spawn(move || {
        server.run().unwrap();
    });

    // Give server a moment to bind
    thread::sleep(Duration::from_millis(200));

    // Run iris-cli binary
    let mut cmd = Command::cargo_bin("iris-cli").unwrap();
    
    // Command: iris-cli -s 127.0.0.1:XXXX test.com
    cmd.arg("-s")
       .arg(&local_addr_str)
       .arg("test.com");

    // Verify CLI output contains the success indicators
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("🔍 Querying"))
        .stdout(predicate::str::contains("✅ Received Response"))
        .stdout(predicate::str::contains("test.com [A]"));
}
