extern crate actix_web;
extern crate dino_park_gate;

use actix_web::{server, App, HttpRequest, Responder};
use dino_park_gate::middleware::AuthMiddleware;
use dino_park_gate::provider::Provider;

fn root(_: &HttpRequest) -> impl Responder {
    "Authorized!"
}

fn main() {
    server::new(|| {
        let provider = Provider::from_issuer("https://auth.mozilla.auth0.com/").unwrap();
        let auth_middleware = AuthMiddleware {
            checker: provider,
            validation_options: Default::default(),
        };

        App::new().resource("/", move |r| {
            r.middleware(auth_middleware);
            r.f(root)
        })
    })
    .bind("127.0.0.1:8000")
    .unwrap()
    .run();
}
