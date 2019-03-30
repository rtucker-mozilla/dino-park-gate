# DinoPark Gate (controlling Dinos since 2019)
[![Build Status](https://travis-ci.org/fiji-flo/dino-park-gate.svg?branch=master)](https://travis-ci.org/fiji-flo/dino-park-gate)

## A basic authentication middleware for [actix-web](https://actix.rs/)

```rust
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
    .unrwap()
    .run();
}
```