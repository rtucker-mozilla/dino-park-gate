use actix_web::HttpResponse;
use actix_web::ResponseError;
use failure::Fail;

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
