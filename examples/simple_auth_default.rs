use actix_web::{web, App, HttpRequest, HttpServer, Responder};
use dino_park_gate::provider::Provider;
use dino_park_gate::simple::SimpleAuth;

async fn root(_: HttpRequest) -> impl Responder {
    "Authorized!"
}

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    let provider = Provider::from_issuer("https://auth.mozilla.auth0.com/")
        .await
        .unwrap();
    HttpServer::new(move || {
        let auth = SimpleAuth {
            checker: provider.clone(),
            validation_options: Default::default(),
        };
        App::new().wrap(auth).service(web::resource("/").to(root))
    })
    .workers(1)
    .bind("127.0.0.1:8000")?
    .run()
    .await
}
