use actix_web::HttpResponse;
use actix_web::ResponseError;
use dino_park_oidc::error::OidcError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("Unauthorized")]
    Unauthorized,
    #[error("Forbidden")]
    Forbidden,
    #[error("oidc error: {0}")]
    OidcError(#[from] OidcError),
    #[error("validation error: {0}")]
    ValidationError(#[from] biscuit::errors::ValidationError),
}

impl ResponseError for ServiceError {
    fn error_response(&self) -> HttpResponse {
        match *self {
            Self::Forbidden => HttpResponse::Forbidden().json("Forbidden"),
            _ => HttpResponse::Unauthorized().json("Unauthorized"),
        }
    }
}
