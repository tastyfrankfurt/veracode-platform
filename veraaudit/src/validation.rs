//! Input validation for CLI parameters
use crate::error::AuditError;
use std::str::FromStr;

/// Valid audit action values from Veracode Reporting API
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditAction {
    Create,
    Delete,
    Update,
    Error,
    Email,
    Success,
    Failed,
    Locked,
    Unlocked,
    LoggedOut,
    Undelete,
    MaintainSchedule,
    PermanentDelete,
    UpdateForInternalOnly,
}

impl AuditAction {
    /// Get the string representation for API calls
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Create => "Create",
            Self::Delete => "Delete",
            Self::Update => "Update",
            Self::Error => "Error",
            Self::Email => "Email",
            Self::Success => "Success",
            Self::Failed => "Failed",
            Self::Locked => "Locked",
            Self::Unlocked => "Unlocked",
            Self::LoggedOut => "Logged out",
            Self::Undelete => "Undelete",
            Self::MaintainSchedule => "Maintain Schedule",
            Self::PermanentDelete => "Permanent Delete",
            Self::UpdateForInternalOnly => "Update for Internal Only",
        }
    }

    /// List all valid values for help text
    #[must_use]
    pub fn valid_values() -> &'static str {
        "Create, Delete, Update, Error, Email, Success, Failed, Locked, Unlocked, 'Logged out', Undelete, 'Maintain Schedule', 'Permanent Delete', 'Update for Internal Only'"
    }
}

impl FromStr for AuditAction {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Create" => Ok(Self::Create),
            "Delete" => Ok(Self::Delete),
            "Update" => Ok(Self::Update),
            "Error" => Ok(Self::Error),
            "Email" => Ok(Self::Email),
            "Success" => Ok(Self::Success),
            "Failed" => Ok(Self::Failed),
            "Locked" => Ok(Self::Locked),
            "Unlocked" => Ok(Self::Unlocked),
            "Logged out" => Ok(Self::LoggedOut),
            "Undelete" => Ok(Self::Undelete),
            "Maintain Schedule" => Ok(Self::MaintainSchedule),
            "Permanent Delete" => Ok(Self::PermanentDelete),
            "Update for Internal Only" => Ok(Self::UpdateForInternalOnly),
            _ => Err(format!(
                "Invalid audit action '{}'. Valid values: {}",
                s,
                Self::valid_values()
            )),
        }
    }
}

/// Valid action type values from Veracode Reporting API
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionType {
    LoginAccount,
    Admin,
    Auth,
    Login,
}

impl ActionType {
    /// Get the string representation for API calls
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::LoginAccount => "Login Account",
            Self::Admin => "Admin",
            Self::Auth => "Auth",
            Self::Login => "Login",
        }
    }

    /// List all valid values for help text
    #[must_use]
    pub fn valid_values() -> &'static str {
        "'Login Account', Admin, Auth, Login"
    }
}

impl FromStr for ActionType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Login Account" => Ok(Self::LoginAccount),
            "Admin" => Ok(Self::Admin),
            "Auth" => Ok(Self::Auth),
            "Login" => Ok(Self::Login),
            _ => Err(format!(
                "Invalid action type '{}'. Valid values: {}",
                s,
                Self::valid_values()
            )),
        }
    }
}

/// Valid Veracode regions
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Region {
    Commercial,
    European,
    Federal,
}

impl Region {
    /// Get the string representation for configuration
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Commercial => "commercial",
            Self::European => "european",
            Self::Federal => "federal",
        }
    }

    /// List all valid values for help text
    #[must_use]
    pub fn valid_values() -> &'static str {
        "commercial, european, federal"
    }
}

impl FromStr for Region {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "commercial" => Ok(Self::Commercial),
            "european" => Ok(Self::European),
            "federal" => Ok(Self::Federal),
            _ => Err(format!(
                "Invalid region '{}'. Valid values: {}",
                s,
                Self::valid_values()
            )),
        }
    }
}

/// Validate cleanup count (must be > 0)
///
/// # Errors
///
/// Returns error if count is 0
pub fn validate_cleanup_count(count: usize) -> Result<usize, AuditError> {
    if count == 0 {
        return Err(AuditError::InvalidConfig(
            "Cleanup count must be greater than 0".to_string(),
        ));
    }
    Ok(count)
}

/// Validate cleanup hours (must be > 0)
///
/// # Errors
///
/// Returns error if hours is 0
pub fn validate_cleanup_hours(hours: u64) -> Result<u64, AuditError> {
    if hours == 0 {
        return Err(AuditError::InvalidConfig(
            "Cleanup hours must be greater than 0".to_string(),
        ));
    }
    Ok(hours)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_action_valid() {
        assert_eq!(
            AuditAction::from_str("Create").unwrap(),
            AuditAction::Create
        );
        assert_eq!(
            AuditAction::from_str("Delete").unwrap(),
            AuditAction::Delete
        );
        assert_eq!(
            AuditAction::from_str("Logged out").unwrap(),
            AuditAction::LoggedOut
        );
        assert_eq!(
            AuditAction::from_str("Maintain Schedule").unwrap(),
            AuditAction::MaintainSchedule
        );
    }

    #[test]
    fn test_audit_action_invalid() {
        assert!(AuditAction::from_str("Invalid").is_err());
        assert!(AuditAction::from_str("create").is_err()); // Case sensitive
    }

    #[test]
    fn test_audit_action_as_str() {
        assert_eq!(AuditAction::Create.as_str(), "Create");
        assert_eq!(AuditAction::LoggedOut.as_str(), "Logged out");
        assert_eq!(AuditAction::MaintainSchedule.as_str(), "Maintain Schedule");
    }

    #[test]
    fn test_action_type_valid() {
        assert_eq!(ActionType::from_str("Admin").unwrap(), ActionType::Admin);
        assert_eq!(
            ActionType::from_str("Login Account").unwrap(),
            ActionType::LoginAccount
        );
        assert_eq!(ActionType::from_str("Auth").unwrap(), ActionType::Auth);
    }

    #[test]
    fn test_action_type_invalid() {
        assert!(ActionType::from_str("Invalid").is_err());
        assert!(ActionType::from_str("admin").is_err()); // Case sensitive
    }

    #[test]
    fn test_region_valid() {
        assert_eq!(Region::from_str("commercial").unwrap(), Region::Commercial);
        assert_eq!(Region::from_str("Commercial").unwrap(), Region::Commercial); // Case insensitive
        assert_eq!(Region::from_str("EUROPEAN").unwrap(), Region::European);
        assert_eq!(Region::from_str("federal").unwrap(), Region::Federal);
    }

    #[test]
    fn test_region_invalid() {
        assert!(Region::from_str("invalid").is_err());
        assert!(Region::from_str("us").is_err());
    }

    #[test]
    fn test_validate_cleanup_count() {
        assert!(validate_cleanup_count(1).is_ok());
        assert!(validate_cleanup_count(100).is_ok());
        assert!(validate_cleanup_count(0).is_err());
    }

    #[test]
    fn test_validate_cleanup_hours() {
        assert!(validate_cleanup_hours(1).is_ok());
        assert!(validate_cleanup_hours(168).is_ok());
        assert!(validate_cleanup_hours(0).is_err());
    }
}
