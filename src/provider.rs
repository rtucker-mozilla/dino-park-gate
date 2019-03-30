use crate::check::TokenChecker;
use crate::error::AuthError;
use crate::remote_keys::RemoteKeys;
use biscuit::jwa;
use biscuit::jwk::AlgorithmParameters;
use biscuit::jws;
use biscuit::Empty;
use condvar_store::CondvarStore;
use failure::Error;
use reqwest::get;
use serde_json::Value;
use url::Url;

#[derive(Debug, Clone)]
pub struct Provider {
    pub issuer: String,
    pub auth_url: Url,
    pub token_url: Url,
    pub user_info_url: Url,
    pub raw_configuration: Value,
    pub remote_key_set: CondvarStore<RemoteKeys>,
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
            remote_key_set: CondvarStore::new(RemoteKeys::new(&p.jwks_uri)?),
        })
    }
}

impl TokenChecker for Provider {
    fn verify_and_decode(&self, token: &str) -> Result<biscuit::ClaimsSet<Value>, Error> {
        let remote = self.remote_key_set.get()?;
        let remote = remote.read().map_err(|_| AuthError::RemoteLockError)?;
        let jwk = remote.keys.get(0).ok_or_else(|| AuthError::NoRemoteKeys)?;
        let rsa = if let AlgorithmParameters::RSA(x) = &jwk.algorithm {
            x
        } else {
            return Err(AuthError::NoRsaJwk.into());
        };
        let c: jws::Compact<biscuit::ClaimsSet<Value>, Empty> = jws::Compact::new_encoded(&token);
        match c.decode(&rsa.jws_public_key_secret(), jwa::SignatureAlgorithm::RS256) {
            Ok(c) => Ok(c.unwrap_decoded().1),
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

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
}
