extern crate actix_web;
extern crate biscuit;
extern crate dino_park_gate;
extern crate env_logger;
extern crate failure;
extern crate shared_expiry_get;
#[macro_use]
extern crate log;

use actix_web::{web, App, HttpRequest, HttpServer, Responder};
use biscuit::ClaimPresenceOptions;
use biscuit::Presence;
use biscuit::StringOrUri;
use biscuit::Validation;
use biscuit::ValidationOptions;
use dino_park_gate::provider::Provider;
use dino_park_gate::simple::SimpleAuth;
use failure::Error;

fn root(_: HttpRequest) -> impl Responder {
    "Authorized!"
}

fn main() -> Result<(), Error> {
    ::std::env::set_var("RUST_LOG", "debug");
    env_logger::init();
    info!("starting");
    HttpServer::new(|| {
        let provider = Provider::from_issuer("https://auth.mozilla.auth0.com/").unwrap();
        let auth = SimpleAuth {
            checker: provider,
            validation_options: ValidationOptions {
                claim_presence_options: ClaimPresenceOptions {
                    audience: Presence::Required,
                    ..Default::default()
                },
                audience: Validation::Validate(StringOrUri::String("foo".into())),
                ..Default::default()
            },
        };

        App::new().wrap(auth).service(web::resource("/").to(root))
    })
    .workers(1)
    .bind("127.0.0.1:8000")
    .unwrap()
    .run()
    .map_err(Into::into)
}