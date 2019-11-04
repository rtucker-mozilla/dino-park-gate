use crate::error::ServiceError;
use crate::provider::Provider;
use actix_service::Service;
use actix_service::Transform;
use actix_web::dev::Payload;
use actix_web::dev::ServiceRequest;
use actix_web::dev::ServiceResponse;
use actix_web::Error;
use actix_web::FromRequest;
use actix_web::HttpMessage;
use actix_web::HttpRequest;
use futures::future::ok;
use futures::future::Future;
use futures::future::FutureResult;
use futures::future::IntoFuture;
use futures::Poll;
use std::cell::RefCell;
use std::sync::Arc;

#[derive(Clone)]
pub struct ScopeAndUser {
    pub user_id: String,
    pub scope: String,
    pub groups_scope: Option<String>,
}

#[derive(Clone)]
pub struct ScopeAndUserAuth {
    pub checker: Provider,
}
#[derive(Clone)]
pub struct ScopeAndUserAuthMiddleware<S> {
    pub service: Arc<RefCell<S>>,
    pub checker: Arc<Provider>,
}

impl<S, B: 'static> Transform<S> for ScopeAndUserAuth
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = ScopeAndUserAuthMiddleware<S>;
    type Future = FutureResult<Self::Transform, Self::InitError>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(ScopeAndUserAuthMiddleware {
            service: Arc::new(RefCell::new(service)),
            checker: Arc::new(self.checker.clone()),
        })
    }
}

impl<S, B> Service for ScopeAndUserAuthMiddleware<S>
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Box<dyn Future<Item = Self::Response, Error = Self::Error>>;

    fn poll_ready(&mut self) -> Poll<(), Self::Error> {
        (*self.service).borrow_mut().poll_ready()
    }

    #[cfg(feature = "localuserscope")]
    fn call(&mut self, req: ServiceRequest) -> Self::Future {
        let svc = self.service.clone();
        Box::new(local_user_scope().into_future().and_then(move |scope| {
            req.extensions_mut().insert(scope);
            (*svc).borrow_mut().call(req)
        }))
    }

    #[cfg(not(feature = "localuserscope"))]
    fn call(&mut self, req: ServiceRequest) -> Self::Future {
        use crate::check::TokenChecker;
        use biscuit::ValidationOptions;

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
                .and_then(|mut claims_set| {
                    if Provider::check(&claims_set, ValidationOptions::default()).is_err() {
                        return Err(ServiceError::Unauthorized.into());
                    }
                    let groups = serde_json::from_value::<Vec<String>>(
                        claims_set.private["https://sso.mozilla.com/claim/groups"].take(),
                    )
                    .ok();
                    let scope = scope_from_claimset(&groups);
                    match scope {
                        None => Err(ServiceError::Unauthorized.into()),
                        Some(scope) => Ok(ScopeAndUser {
                            user_id,
                            scope,
                            groups_scope: groups_scope_from_claimset(&groups),
                        }),
                    }
                })
                .and_then(move |scope| {
                    req.extensions_mut().insert(scope);
                    (*svc).borrow_mut().call(req)
                }),
        )
    }
}

impl FromRequest for ScopeAndUser {
    type Config = ();
    type Error = Error;
    type Future = Result<Self, Error>;

    #[inline]
    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        if let Some(scope_and_user) = req.extensions().get::<ScopeAndUser>() {
            Ok(scope_and_user.clone())
        } else {
            Err(ServiceError::Unauthorized.into())
        }
    }
}

#[cfg(not(feature = "localuserscope"))]
fn scope_from_claimset(claims_set: &Option<Vec<String>>) -> Option<String> {
    if let Some(groups) = claims_set {
        let scope = if groups.contains(&String::from("team_moco"))
            || groups.contains(&String::from("team_mofo"))
            || groups.contains(&String::from("team_mozillaonline"))
            || groups.contains(&String::from("hris_is_staff"))
        {
            String::from("staff")
        } else if groups.contains(&String::from("mozilliansorg_nda")) {
            String::from("ndaed")
        } else {
            String::from("authenticated")
        };
        return Some(scope);
    }
    None
}

#[cfg(not(feature = "localuserscope"))]
fn groups_scope_from_claimset(claims_set: &Option<Vec<String>>) -> Option<String> {
    if let Some(groups) = claims_set {
        if groups.contains(&String::from("mozilliansorg_group_admins")) {
            return Some(String::from("admin"));
        }
        if groups.contains(&String::from("mozilliansorg_group_creators")) {
            return Some(String::from("creator"));
        }
    }
    None
}

#[cfg(feature = "localuserscope")]
fn local_user_scope() -> Result<ScopeAndUser, Error> {
    use failure::format_err;
    use log::info;
    use std::env::var;

    let DPG_USERSCOPE = "DPG_USERSCOPE";
    let user_scope =
        var(DPG_USERSCOPE).map_err(|_| format_err!("{} not defined", DPG_USERSCOPE))?;
    info!("using {}: {}", DPG_USERSCOPE, user_scope);
    let mut tuple = user_scope.split(',');
    let user_id = tuple
        .next()
        .ok_or_else(|| format_err!("{}: no user_id", DPG_USERSCOPE))?
        .to_owned();
    let scope = tuple
        .next()
        .ok_or_else(|| format_err!("{}: no scope", DPG_USERSCOPE))?
        .to_owned();
    let groups_scope = tuple.next().map(|s| s.to_owned());
    Ok(ScopeAndUser {
        user_id,
        scope,
        groups_scope,
    })
}
