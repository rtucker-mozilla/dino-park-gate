#[macro_use]
extern crate serde_derive;

use std::future::Future;
use std::pin::Pin;

pub mod check;
pub mod error;
pub mod provider;
pub mod remote_keys;
pub mod scope;
pub mod settings;
pub mod simple;

type BoxFut<T, E> = Pin<Box<dyn Future<Output = Result<T, E>>>>;
