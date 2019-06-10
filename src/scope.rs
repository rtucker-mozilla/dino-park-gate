use crate::check::TokenChecker;
use crate::error::ServiceError;
use crate::provider::Provider;
use actix_service::Service;
use actix_service::Transform;
use actix_web::dev::ServiceRequest;
use actix_web::dev::ServiceResponse;
use actix_web::Error;
use biscuit::ClaimsSet;
use biscuit::ValidationOptions;
use futures::future::ok;
use futures::future::Future;
use futures::future::FutureResult;
use futures::future::IntoFuture;
use futures::Poll;
use serde_json::Value;

use std::cell::RefCell;
use std::sync::Arc;

pub struct ScopeAndUser {
    pub user_id: String,
    pub scope: String,
}

#[derive(Clone)]
pub struct TokenCheckerWithValidation {
    pub checker: Provider,
}
#[derive(Clone)]
pub struct ScopeAndUserMiddleware<S> {
    pub service: Arc<RefCell<S>>,
    pub checker: Arc<Provider>,
}

impl<S, B: 'static> Transform<S> for TokenCheckerWithValidation
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = ScopeAndUserMiddleware<S>;
    type Future = FutureResult<Self::Transform, Self::InitError>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(ScopeAndUserMiddleware {
            service: Arc::new(RefCell::new(service)),
            checker: Arc::new(self.checker.clone()),
        })
    }
}

impl<S, B> Service for ScopeAndUserMiddleware<S>
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
        let auth_token = match req
            .headers()
            .get("x-auth-token")
            .and_then(|value| value.to_str().ok())
        {
            Some(auth_token) => auth_token.to_owned(),
            None => return Box::new(Err(ServiceError::Unauthorized.into()).into_future()),
        };
        let user_id = match req
            .headers()
            .get("x-forwarded-user-subject")
            .or_else(|| req.headers().get("x-auth-subject"))
            .and_then(|id| id.to_str().ok())
            .map(|id| id.to_owned())
        {
            Some(user_id) => user_id,
            None => return Box::new(Err(ServiceError::Unauthorized.into()).into_future()),
        };

        let svc = self.service.clone();
        Box::new(
            self.checker
                .verify_and_decode(auth_token)
                .map_err(|_| ServiceError::Unauthorized.into())
                .and_then(|claims_set| {
                    if Provider::check(&claims_set, ValidationOptions::default()).is_err() {
                        return Err(ServiceError::Unauthorized.into());
                    }
                    let scope = scope_from_claimset(claims_set);
                    match scope {
                        None => Err(ServiceError::Unauthorized.into()),
                        Some(scope) => Ok(ScopeAndUser { user_id, scope }),
                    }
                })
                .and_then(move |_| (*svc).borrow_mut().call(req)),
        )
    }
}

fn scope_from_claimset(claims_set: ClaimsSet<Value>) -> Option<String> {
    if let Some(groups) = claims_set.private["https://sso.mozilla.com/claim/groups"]
        .as_str()
        .map(|groups| groups.split(',').collect::<Vec<&str>>())
    {
        if groups.contains(&"team_moco") || groups.contains(&"team_moco") {
            info!("scope → staff");
            return Some(String::from("staff"));
        }
        if groups.contains(&"mozilliansorg_nda") {
            return Some(String::from("ndaed"));
        }
        return Some(String::from("authenticated"));
    }
    None
}
