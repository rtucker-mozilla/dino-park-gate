use crate::error::ServiceError;
use biscuit::ValidationOptions;
use dino_park_oidc::provider::check;
use dino_park_oidc::provider::Provider;
use futures::Future;
use futures::{future::BoxFuture, TryFutureExt};
use serde_json::Value;

pub trait TokenChecker {
    type Item;
    type Future: Future<Output = Result<Self::Item, ServiceError>>;
    fn verify_and_decode(&self, token: String) -> Self::Future;
    fn check(item: &Self::Item, validation_options: ValidationOptions) -> Result<(), ServiceError>;
}

impl TokenChecker for Provider {
    type Item = biscuit::ClaimsSet<Value>;
    type Future = BoxFuture<'static, Result<Self::Item, ServiceError>>;
    fn verify_and_decode(&self, token: String) -> Self::Future {
        Box::pin(self.verify_and_decode(token).map_err(Into::into))
    }
    fn check(item: &Self::Item, validation_options: ValidationOptions) -> Result<(), ServiceError> {
        check(item, validation_options).map_err(Into::into)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use biscuit::ClaimsSet;
    use biscuit::RegisteredClaims;
    use biscuit::SingleOrMultiple;
    use serde_json::Value;

    #[tokio::test]
    async fn test_from_issuer_mozilla() {
        let p = Provider::from_issuer("https://auth.mozilla.auth0.com/");
        assert!(p.await.is_ok());
    }

    #[tokio::test]
    async fn test_from_issuer_google() {
        let p = Provider::from_issuer("https://accounts.google.com/");
        assert!(p.await.is_ok());
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
                    audience: Some(SingleOrMultiple::Single("foo".to_string())),
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
