use biscuit::ClaimsSet;
use biscuit::ValidationOptions;
use failure::Error;
use serde_json::Value;

pub trait TokenChecker {
    fn verify_and_decode(&self, token: &str) -> Result<biscuit::ClaimsSet<Value>, Error>;
}

pub fn check_claim_set(
    claim_set: &ClaimsSet<Value>,
    validation_options: ValidationOptions,
) -> Result<(), Error> {
    claim_set
        .registered
        .validate(validation_options)
        .map_err(Into::into)
}

#[cfg(test)]
mod test {
    use super::*;
    use biscuit::ClaimsSet;
    use biscuit::RegisteredClaims;
    use biscuit::SingleOrMultiple;
    use biscuit::StringOrUri;

    #[test]
    fn test_validate_empty_sets() {
        let claim_set = ClaimsSet {
            registered: Default::default(),
            private: Value::default(),
        };
        let validation_options = ValidationOptions::default();
        let res = check_claim_set(&claim_set, validation_options);
        assert!(res.is_ok());
    }

    #[test]
    fn test_validate_audience() {
        let claim_set = ClaimsSet {
            registered: {
                RegisteredClaims {
                    audience: Some(SingleOrMultiple::Single(StringOrUri::String(
                        "foo".to_string(),
                    ))),
                    ..Default::default()
                }
            },
            private: Value::default(),
        };
        let validation_options = ValidationOptions::default();
        let res = check_claim_set(&claim_set, validation_options);
        assert!(res.is_ok());
    }
}
