Unix only [`oidc-agent`]( https://indigo-dc.gitbook.io/oidc-agent ) library for Rust

 ## Description

 This crate is an interface to `oidc-agent` IPC-API.

 The `oidc-agent` must be running under the user system and OIDC_SOCK must be exported properly.

 ## Obtaining access_token
 ### Basic usage
 To obtain access_token by profile shortname from the agent run the following code in `main.rs`:
 ```rust
 use oidc_agent_rs::Agent;
 use std::error::Error;

 fn main() -> Result<(), Box<dyn Error>> {
    let agent = Agent::new()?;
    let access_token = agent.get_access_token("profile_shortname")?;

    println!("{}", access_token.secret());
    Ok(())
 }
 ```
 The `secret()` method is required to obtain token as a `&str` value. Otherwise the Token pseudostruct
 would be returned.

 ### Advanced requests
 To obtain access_token with more advanced options you have to use request builder.
 `AccessTokenRequest` has a method to easy build a new request. Then you have to send the request
 directly to the agent and parse the response.

 Example:
 ```rust
 use oidc_agent_rs::{requests::AccessTokenRequest, Agent};
 use std::error::Error;

 fn main() -> Result<(), Box<dyn Error>> {
     let agent = Agent::new()?;
     
     //obtaining access_token by issuer only (no shortname needed)
     let at_request = AccessTokenRequest::builder()
         .issuer("https://issuer.url")?
         .min_valid_period(60)
         .build()?;

     let at_response = agent.send_request(at_request)?;

     println!("{}", at_response.access_token().secret());
     println!("{}", at_response.issuer());
     println!("{}", at_response.expires_at());

     Ok(())
 }
 ```

 ## Obtaining mytoken
 ### Basic usage
 Obtaining [ `mytoken` ](https://mytoken-docs.data.kit.edu/) using only profile shortname is very similar to obtaining access_token.

 Example:
 ```
 use oidc_agent_rs::Agent;
 use std::error::Error;

 fn main() -> Result<(), Box<dyn Error>> {
     let agent = Agent::new()?;

     let mytoken = agent.get_mytoken("mytoken")?;

     println!("{}", mytoken.secret());

     Ok(())
 }
 ```

 ### Advanced requests
 If you want to obtain new mytoken using specific Mytoken profile, you have to create new
 `mytoken::Profile` element. This takes 0 or more `mytoken::Capability`, 0 or more `mytoken::Restriction` and one or
 none `mytoken::Rotation`. Empty profile is possible but not recommended.

 Example:

```rust
 use oidc_agent_rs::mytoken::{Capability, Profile, Restriction, Rotation, TokenInfoPerms};
 use oidc_agent_rs::requests::MyTokenRequest;
 use oidc_agent_rs::Agent;
 use std::error::Error;

 fn main() -> Result<(), Box<dyn Error>> {
     let agent = Agent::new()?;
     let mut profile = Profile::new();

     //basic capabilites
     let caps = vec![Capability::AT, Capability::TokenInfo(TokenInfoPerms::All)];

     //new restriction
     let restriction = Restriction::builder()
         .usages_AT(5) //number of mytoken max usages
         .add_geoip_allow(vec!["pl", "de"]) //geoip allowed regions
         .build();

     //basic rotation
     let rotation = Rotation::builder().set_on_AT().set_lifetime(1000).build()?;

     profile.add_capabilities(&caps);
     profile.add_restrictions(&vec![restriction]);
     profile.set_rotation(&rotation);

     let mt_request = MyTokenRequest::builder("mytoken")
         .mytoken_profile(&profile)
         .build()?;

     let mt_response = agent.send_request(mt_request)?;

     println!("{}", mt_response.mytoken().secret());

     Ok(())
 }
```

