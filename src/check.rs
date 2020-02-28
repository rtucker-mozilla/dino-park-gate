use biscuit::ValidationOptions;
use dino_park_oidc::provider::check;
use dino_park_oidc::provider::Provider;
use failure::Error;
use futures::future::BoxFuture;
use futures::Future;
use serde_json::Value;

pub trait TokenChecker {
    type Item;
    type Future: Future<Output = Result<Self::Item, Error>>;
    fn verify_and_decode(&self, token: String) -> Self::Future;
    fn check(item: &Self::Item, validation_options: ValidationOptions) -> Result<(), Error>;
}

impl TokenChecker for Provider {
    type Item = biscuit::ClaimsSet<Value>;
    type Future = BoxFuture<'static, Result<Self::Item, Error>>;
    fn verify_and_decode(&self, token: String) -> Self::Future {
        self.verify_and_decode(token)
    }
    fn check(item: &Self::Item, validation_options: ValidationOptions) -> Result<(), Error> {
        check(item, validation_options)
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
    use tokio_test::block_on;

    #[test]
    fn test_from_issuer_mozilla() {
        let p = Provider::from_issuer("https://auth.mozilla.auth0.com/");
        assert!(block_on(p).is_ok());
    }

    #[test]
    fn test_from_issuer_google() {
        let p = Provider::from_issuer("https://accounts.google.com/");
        assert!(block_on(p).is_ok());
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
