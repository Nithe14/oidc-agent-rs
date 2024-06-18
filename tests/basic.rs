use oidc_agent_rs::*;
#[test]
fn test_basic() {
    let client = Client::new().unwrap();
    assert_eq!(
        client.get_socket_path(),
        Some("/tmp/oidc-agent-service-1000/oidc-agent.sock")
    );
}

#[test]
fn test_1() {
    let client = Client::new().unwrap();
    let access_token = client.get_access_token("mytoken");
    assert!(access_token.is_ok());
    let mytoken = client.get_mytoken("mytoken");
    assert!(mytoken.is_err());

    let loaded_accounts = client.get_loaded_accounts().unwrap();
    assert_eq!(
        loaded_accounts,
        vec!["nowy".to_string(), "mytoken".to_string()]
    );
}
