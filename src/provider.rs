use crate::check::TokenChecker;
use crate::error::AuthError;
use crate::remote_keys::RemoteKeys;
use crate::remote_keys::RemoteKeysProvider;
use biscuit::jwa;
use biscuit::jwk::AlgorithmParameters;
use biscuit::jws;
use biscuit::Empty;
use biscuit::ValidationOptions;
use failure::Error;
use futures::Future;
use log::debug;
use reqwest::get;
use serde_json::Value;
use shared_expiry_get::RemoteStore;
use url::Url;

#[derive(Clone)]
pub struct Provider {
    pub issuer: String,
    pub auth_url: Url,
    pub token_url: Url,
    pub user_info_url: Url,
    pub raw_configuration: Value,
    pub remote_key_set: RemoteStore<RemoteKeys, RemoteKeysProvider>,
}

#[derive(Serialize, Deserialize, Debug)]
struct ProviderJson {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    userinfo_endpoint: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Scopes {
    scopes_supported: Vec<String>,
    claims_supported: Vec<String>,
}

impl Provider {
    pub fn from_issuer(issuer: &str) -> Result<Self, Error> {
        let well_known =
            Url::parse(issuer).and_then(|u| u.join(".well-known/openid-configuration"))?;
        let res: Value = get(well_known)?.error_for_status()?.json()?;

        let p: ProviderJson = serde_json::from_value(res.clone())?;

        if p.issuer.trim_end_matches('/') != issuer.trim_end_matches('/') {
            return Err(AuthError::IssuerMismatch.into());
        }

        Ok(Provider {
            issuer: p.issuer,
            auth_url: Url::parse(&p.authorization_endpoint)?,
            token_url: Url::parse(&p.token_endpoint)?,
            user_info_url: Url::parse(&p.userinfo_endpoint)?,
            raw_configuration: res,
            remote_key_set: RemoteStore::new(RemoteKeysProvider::new(&p.jwks_uri)?),
        })
    }
}

impl TokenChecker for Provider {
    type Item = biscuit::ClaimsSet<Value>;
    type Future = Box<dyn Future<Item = Self::Item, Error = Error> + 'static>;
    fn verify_and_decode(&self, token: String) -> Self::Future {
        debug!("verify and decode");
        let token = token.to_owned();
        Box::new(self.remote_key_set.get().and_then(move |remote| {
            let jwk = remote.keys.get(0).ok_or_else(|| AuthError::NoRemoteKeys)?;
            let rsa = if let AlgorithmParameters::RSA(x) = &jwk.algorithm {
                x
            } else {
                return Err(AuthError::NoRsaJwk.into());
            };
            let c: jws::Compact<biscuit::ClaimsSet<Value>, Empty> =
                jws::Compact::new_encoded(&token);
            match c.decode(&rsa.jws_public_key_secret(), jwa::SignatureAlgorithm::RS256) {
                Ok(c) => Ok(c.unwrap_decoded().1),
                Err(e) => Err(e.into()),
            }
        }))
    }
    fn check(item: &Self::Item, validation_options: ValidationOptions) -> Result<(), Error> {
        item.registered
            .validate(validation_options)
            .map_err(Into::into)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use biscuit::ClaimsSet;
    use biscuit::RegisteredClaims;
    use biscuit::SingleOrMultiple;
    use biscuit::StringOrUri;
    use serde_json::Value;

    #[test]
    fn test_from_issuer_mozilla() {
        let p = Provider::from_issuer("https://auth.mozilla.auth0.com/");
        assert!(p.is_ok());
    }

    #[test]
    fn test_from_issuer_google() {
        let p = Provider::from_issuer("https://accounts.google.com/");
        assert!(p.is_ok());
    }

    #[test]
    fn test_validate_empty_sets() {
        let claim_set = ClaimsSet {
            registered: Default::default(),
            private: Value::default(),
        };
        let validation_options = ValidationOptions::default();
        let res = Provider::check(&claim_set, validation_options);
        assert!(res.is_ok());
    }

    #[test]
    fn test_validate_audience() {
        let claim_set = ClaimsSet {
            registered: {
                RegisteredClaims {
                    audience: Some(SingleOrMultiple::Single(StringOrUri::String(
                        "foo".to_string(),
                    ))),
                    ..Default::default()
                }
            },
            private: Value::default(),
        };
        let validation_options = ValidationOptions::default();
        let res = Provider::check(&claim_set, validation_options);
        assert!(res.is_ok());
    }
}
