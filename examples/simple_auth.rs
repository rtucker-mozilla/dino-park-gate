extern crate actix_web;
extern crate dino_park_gate;
extern crate failure;
extern crate env_logger;
#[macro_use]
extern crate log;
extern crate shared_expiry_get;

use actix_web::{web, App, HttpRequest, HttpServer, Responder};
use dino_park_gate::simple::SimpleAuth;
use dino_park_gate::provider::Provider;
use failure::Error;

fn root(_: HttpRequest) -> impl Responder {
    "Authorized!"
}

fn main() -> Result<(), Error> {
    ::std::env::set_var("RUST_LOG", "simple_auth=info,actix_web=debug,dino_park_gate=info,shared_expiry_get=debug");
    env_logger::init();
    info!("starting");
    HttpServer::new(|| {
        let provider = Provider::from_issuer("https://auth.mozilla.auth0.com/").unwrap();
        let auth = SimpleAuth {
            checker: provider,
            validation_options: Default::default(),
        };

        App::new().wrap(auth).service(web::resource("/").to(root))
    })
    .workers(2)
    .bind("127.0.0.1:8000")
    .unwrap()
    .run()
    .map_err(Into::into)
}
