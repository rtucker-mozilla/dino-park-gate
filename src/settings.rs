use biscuit::ClaimPresenceOptions;
use biscuit::Presence;
use biscuit::StringOrUri;
use biscuit::Validation;
use biscuit::ValidationOptions;
use chrono::Duration;

#[derive(Debug, Deserialize, Clone, Default)]
pub struct AuthValidationSettings {
    pub audience: Option<String>,
    pub issuer: Option<String>,
    pub issued_at: Option<i64>,
}

impl AuthValidationSettings {
    pub fn to_validation_options(&self) -> ValidationOptions {
        let claim_presence_options = ClaimPresenceOptions {
            audience: self
                .audience
                .as_ref()
                .map(|_| Presence::Required)
                .unwrap_or_default(),
            expiry: Presence::Required,
            issuer: self
                .issuer
                .as_ref()
                .map(|_| Presence::Required)
                .unwrap_or_default(),
            issued_at: self
                .issued_at
                .map(|_| Presence::Required)
                .unwrap_or_default(),
            ..Default::default()
        };
        ValidationOptions {
            claim_presence_options,
            audience: self
                .audience
                .as_ref()
                .map(|s| Validation::Validate(StringOrUri::String(s.clone())))
                .unwrap_or_default(),
            issuer: self
                .issuer
                .as_ref()
                .map(|s| Validation::Validate(StringOrUri::String(s.clone())))
                .unwrap_or_default(),
            issued_at: self
                .issued_at
                .map(|s| Validation::Validate(Duration::seconds(s)))
                .unwrap_or_default(),
            ..Default::default()
        }
    }
}
