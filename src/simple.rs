use crate::check::TokenChecker;
use crate::error::ServiceError;
use actix_service::Service;
use actix_service::Transform;
use actix_web::dev::ServiceRequest;
use actix_web::dev::ServiceResponse;
use actix_web::Error;
use biscuit::ValidationOptions;

use futures::future::ok;

use futures::future::Future;
use futures::future::FutureResult;
use futures::future::IntoFuture;
use futures::Poll;

use std::cell::RefCell;
use std::sync::Arc;

#[derive(Clone)]
pub struct SimpleAuth<T: TokenChecker + 'static> {
    pub checker: T,
    pub validation_options: ValidationOptions,
}
#[derive(Clone)]
pub struct SimpleAuthMiddleware<S, T: TokenChecker + 'static> {
    pub service: Arc<RefCell<S>>,
    pub checker: Arc<T>,
    pub validation_options: ValidationOptions,
}

impl<S, B: 'static, T: TokenChecker + Clone + 'static> Transform<S> for SimpleAuth<T>
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = SimpleAuthMiddleware<S, T>;
    type Future = FutureResult<Self::Transform, Self::InitError>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(SimpleAuthMiddleware {
            service: Arc::new(RefCell::new(service)),
            checker: Arc::new(self.checker.clone()),
            validation_options: self.validation_options.clone(),
        })
    }
}

impl<S, B, T: TokenChecker + 'static> Service for SimpleAuthMiddleware<S, T>
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Box<Future<Item = Self::Response, Error = Self::Error>>;

    fn poll_ready(&mut self) -> Poll<(), Self::Error> {
        (*self.service).borrow_mut().poll_ready()
    }

    fn call(&mut self, req: ServiceRequest) -> Self::Future {
        if req.method() == "OPTIONS" {
            return Box::new((*self.service).borrow_mut().call(req));
        }

        let auth_header = match req.headers().get("AUTHORIZATION") {
            Some(value) => value.to_str().ok(),
            None => return Box::new(Err(ServiceError::Unauthorized.into()).into_future()),
        };

        if let Some(auth_header) = auth_header {
            if let Some(token) = get_token(auth_header) {
                let svc = self.service.clone();
                let validation_options = self.validation_options.clone();
                let f: Box<Future<Item = _, Error = Error> + 'static> = Box::new(
                    self.checker
                        .verify_and_decode(token.to_owned())
                        .map_err(Into::into)
                        .and_then(|claim_set| T::check(claim_set, validation_options))
                        .map_err(|_| ServiceError::Unauthorized.into()),
                );
                let b: Box<Future<Item = ServiceResponse<B>, Error = Error> + 'static> =
                    Box::new(f.and_then(move |_| (*svc).borrow_mut().call(req)));

                return b;
            }
        }
        Box::new(Err(ServiceError::Unauthorized.into()).into_future())
    }
}

fn get_token(auth_header: &str) -> Option<&str> {
    match auth_header.get(0..7) {
        Some("Bearer ") => auth_header.get(7..),
        _ => None,
    }
}
/*
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
*/
