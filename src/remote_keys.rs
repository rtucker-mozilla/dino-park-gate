use biscuit::jwk::JWK;
use biscuit::Empty;
use chrono::DateTime;
use chrono::Duration;
use chrono::TimeZone;
use chrono::Utc;
use condvar_store::GetExpiry;
use failure::Error;
use reqwest::get;
use serde_json::Value;
use url::Url;

#[derive(Debug)]
pub struct RemoteKeys {
    pub jwk_url: Url,
    pub keys: Vec<JWK<Empty>>,
    pub expiry: DateTime<Utc>,
}

impl RemoteKeys {
    pub fn new(jwk_url_str: &str) -> Result<Self, Error> {
        let jwk_url = Url::parse(jwk_url_str)?;
        Ok(RemoteKeys {
            jwk_url,
            keys: vec![],
            expiry: Utc.timestamp(0, 0),
        })
    }
}

impl GetExpiry for RemoteKeys {
    fn get(&mut self) -> Result<(), Error> {
        let mut keys: Value = get(self.jwk_url.clone())?.json()?;
        let jwks: Vec<JWK<Empty>> = serde_json::from_value(keys["keys"].take())?;
        self.keys = jwks;
        self.expiry = Utc::now() + Duration::days(1);
        Ok(())
    }
    fn expiry(&self) -> DateTime<Utc> {
        self.expiry
    }
}
