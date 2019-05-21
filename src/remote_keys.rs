use biscuit::jwk::JWK;
use biscuit::Empty;
use chrono::DateTime;
use chrono::Duration;
use chrono::Utc;
use failure::Error;
use futures::future;
use futures::Future;
use futures::IntoFuture;
use reqwest::Client;
use serde_json::Value;
use shared_expiry_get::Expiry;
use shared_expiry_get::Provider;
use url::Url;

pub struct RemoteKeysProvider {
    pub jwk_url: Url,
}

#[derive(Debug, Clone)]
pub struct RemoteKeys {
    pub keys: Vec<JWK<Empty>>,
    pub expiry: DateTime<Utc>,
}

impl RemoteKeysProvider {
    pub fn new(jwk_url_str: &str) -> Result<Self, Error> {
        let jwk_url = jwk_url_str.parse()?;
        Ok(RemoteKeysProvider { jwk_url })
    }
}

impl Provider<RemoteKeys> for RemoteKeysProvider {
    fn update(&self) -> Box<Future<Item = RemoteKeys, Error = Error> + Send> {
        info!("updating: {}", self.jwk_url);
        let keys = get_keys(self.jwk_url.clone());
        Box::new(
            keys.and_then(|jwks| {
                future::ok(RemoteKeys {
                    keys: jwks,
                    expiry: Utc::now() + Duration::days(1),
                })
            })
            .map_err(Into::into),
        )
    }
}
impl Expiry for RemoteKeys {
    fn valid(&self) -> bool {
        info!("valid?");
        self.expiry > Utc::now()
    }
}

fn get_keys(url: Url) -> Box<Future<Item = Vec<JWK<Empty>>, Error = Error> + Send> {
    info!("getting keys");
        let res = Client::new()
            .get(url)
            .send()
            .map_err(Error::from);
            info!("{:#?}", res);
            let json = res.unwrap().json().map_err(Into::into);
            info!("{:#?}", json);

/*
            res.into_future().and_then(|mut r| {
                info!("res");
                r.json().map_err(Into::into)
            })
            */
    Box::new(
            json.into_future().and_then(|mut keys: Value| {
                serde_json::from_value::<Vec<JWK<Empty>>>(keys["keys"].take()).map_err(Into::into)
            }),
    )
}
