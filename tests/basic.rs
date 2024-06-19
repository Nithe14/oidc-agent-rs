use mytoken::Capability;
use oidc_agent_rs::*;

#[test]
fn test_basic() {
    let client = Agent::new().unwrap();
    assert_eq!(
        client.get_socket_path(),
        Some("/tmp/oidc-agent-service-1000/oidc-agent.sock")
    );
}

#[test]
fn test_1() {
    let client = Agent::new().unwrap();
    let access_token = client.get_access_token("mytoken");
    assert!(access_token.is_ok());
    let mytoken = client.get_mytoken("mytoken").unwrap();
    println!("{}", mytoken);
    //assert!(mytoken.is_err());

    let loaded_accounts = client.get_loaded_accounts().unwrap();
    assert_eq!(loaded_accounts, vec!["mytoken".to_string()]);
}

#[test]
fn test_caps() {
    let cap = Capability::MytokenCreate;
    let serialized = serde_json::to_string(&cap).unwrap();

    let cap1 = serde_json::json!("tokeninfo:introspect");
    let des: Capability = serde_json::from_value(cap1).unwrap();
    println!("{}", serialized);
    println!("{:#?}", des);
    assert_eq!(&serialized, "tokeninfo:subtokens");
}
