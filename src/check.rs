use biscuit::ValidationOptions;
use failure::Error;
use futures::Future;

pub trait TokenChecker {
    type Item;
    type Future: Future<Output = Result<Self::Item, Error>>;
    fn verify_and_decode(&self, token: String) -> Self::Future;
    fn check(item: &Self::Item, validation_options: ValidationOptions) -> Result<(), Error>;
}
