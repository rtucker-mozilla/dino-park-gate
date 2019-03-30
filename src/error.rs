use actix_web::HttpResponse;
use actix_web::ResponseError;

#[derive(Debug, Fail)]
pub enum AuthError {
    #[fail(display = "unable to get read lock for remote keys")]
    RemoteLockError,
    #[fail(display = "no remote keys")]
    NoRemoteKeys,
    #[fail(display = "issuer mismatch")]
    IssuerMismatch,
    #[fail(display = "no rsa jwk")]
    NoRsaJwk,
}

#[derive(Debug, Fail)]
pub enum ServiceError {
    #[fail(display = "Unauthorized")]
    Unauthorized,
}

impl ResponseError for ServiceError {
    fn error_response(&self) -> HttpResponse {
        match *self {
            ServiceError::Unauthorized => HttpResponse::Unauthorized().json("Unauthorized"),
        }
    }
}
