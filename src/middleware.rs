use crate::check::check_claim_set;
use crate::check::TokenChecker;
use crate::error::ServiceError;
use actix_web::middleware::Middleware;
use actix_web::middleware::Started;
use actix_web::HttpRequest;
use actix_web::Result;
use biscuit::ValidationOptions;

#[derive(Clone)]
pub struct AuthMiddleware<T: TokenChecker + 'static> {
    pub checker: T,
    pub validation_options: ValidationOptions,
}

impl<T: TokenChecker, S> Middleware<S> for AuthMiddleware<T> {
    fn start(&self, req: &HttpRequest<S>) -> Result<Started> {
        if req.method() == "OPTIONS" {
            return Ok(Started::Done);
        }

        let auth_header = req
            .headers()
            .get("AUTHORIZATION")
            .map(|value| value.to_str().ok())
            .ok_or(ServiceError::Unauthorized)?;

        if let Some(auth_header) = auth_header {
            if let Some(token) = get_token(auth_header) {
                let claim_set = self.checker.verify_and_decode(&token)?;
                check_claim_set(&claim_set, self.validation_options.clone())?;
                return Ok(Started::Done);
            }
        }
        Err(ServiceError::Unauthorized.into())
    }
}

fn get_token(auth_header: &str) -> Option<&str> {
    match auth_header.get(0..7) {
        Some("Bearer ") => auth_header.get(7..),
        _ => None,
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use actix_web::test::TestRequest;
    use biscuit::ClaimsSet;
    use failure::Error;
    use serde_json::Value;

    #[derive(Default, Clone)]
    struct FakeChecker {
        pub claim_set: Option<ClaimsSet<Value>>,
        pub token: Option<String>,
    }

    impl TokenChecker for FakeChecker {
        fn verify_and_decode(&self, token: &str) -> Result<ClaimsSet<Value>, Error> {
            if let Some(cs) = &self.claim_set {
                if self
                    .token
                    .as_ref()
                    .map(|t| t == token)
                    .unwrap_or_else(|| true)
                {
                    return Ok(cs.clone());
                }
            };
            return Err(ServiceError::Unauthorized.into());
        }
    }

    #[test]
    fn test_get_token() {
        let token = "Bearer FOOBAR…";
        assert_eq!(get_token(token), Some("FOOBAR…"));
    }

    #[test]
    fn test_middleware_no_token() {
        let auth_middleware = AuthMiddleware {
            checker: FakeChecker::default(),
            validation_options: ValidationOptions::default(),
        };
        let req = TestRequest::with_header("SOMETHING", "ELSE").finish();
        let res = auth_middleware.start(&req);
        assert!(res.is_err());
    }

    #[test]
    fn test_middleware_bearer_missing() {
        let auth_middleware = AuthMiddleware {
            checker: FakeChecker {
                claim_set: Some(ClaimsSet {
                    registered: Default::default(),
                    private: Value::default(),
                }),
                token: None,
            },
            validation_options: ValidationOptions::default(),
        };
        let req = TestRequest::with_header("AUTHORIZATION", "not bearer").finish();
        let res = auth_middleware.start(&req);
        assert!(res.is_err());
    }

    #[test]
    fn test_middleware_authorized() {
        let auth_middleware = AuthMiddleware {
            checker: FakeChecker {
                claim_set: Some(ClaimsSet {
                    registered: Default::default(),
                    private: Value::default(),
                }),
                token: None,
            },
            validation_options: ValidationOptions::default(),
        };
        let req = TestRequest::with_header("AUTHORIZATION", "Bearer somethingfun").finish();
        let res = auth_middleware.start(&req);
        assert!(res.is_ok());
    }
}
