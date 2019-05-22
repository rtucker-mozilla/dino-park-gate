use biscuit::ValidationOptions;
use failure::Error;
use futures::Future;

pub trait TokenChecker {
    type Item;
    type Future: Future<Item = Self::Item, Error = Error> + 'static;
    type CheckFuture: Future<Item = (), Error = Error> + 'static;
    fn verify_and_decode(&self, token: String) -> Self::Future;
    fn check(item: Self::Item, validation_options: ValidationOptions) -> Self::CheckFuture;
}
