# Defensive Programming Implementation Checklist

This checklist tracks the implementation of defensive programming recommendations from the security code review of `veracode-api/src/app.rs`.

## Progress Summary
- ✅ **2 Critical fixes completed**
- ✅ **3 High priority fixes completed**
- ✅ **3 Medium priority fixes completed**
- 📝 **1 Low priority remaining** (1 completed)

---

## ✅ COMPLETED

### 1. Create Validation Module (CRITICAL)
**Status**: ✅ COMPLETE
**File**: `src/validation.rs`

- [x] Created validation module with comprehensive error types
- [x] Implemented `AppGuid` type with UUID validation
- [x] Implemented `AppName` type with length/character validation
- [x] Implemented `Description` type with length validation
- [x] Added validation constants (max lengths, pagination limits)
- [x] Added `ValidationError` enum
- [x] Added unit tests for all validators
- [x] Integrated with `VeracodeError` enum

### 2. Fix URL Path Injection Vulnerability (CRITICAL)
**Status**: ✅ COMPLETE
**Files**: `src/app.rs`, `src/workflow.rs`

- [x] Updated `get_application()` to use `AppGuid`
- [x] Updated `update_application()` to use `AppGuid`
- [x] Updated `delete_application()` to use `AppGuid`
- [x] Updated `get_app_id_from_guid()` to use `AppGuid`
- [x] Updated `enable_application_encryption()` to use `AppGuid`
- [x] Updated `change_encryption_key()` to use `AppGuid`
- [x] Updated `get_application_encryption_status()` to use `AppGuid`
- [x] Fixed all workflow.rs usages
- [x] Added `#[must_use]` annotations to key methods
- [x] Verified compilation success

### 3. Fix Query Parameter Injection (HIGH PRIORITY)
**Status**: ✅ COMPLETE
**Files**: `src/validation.rs`, `src/app.rs`

- [x] Added URL encoding functions to validation module (`encode_query_param`, `build_query_param`)
- [x] Updated `ApplicationQuery::to_query_params()` implementations to encode all values
- [x] Added comprehensive unit tests for injection attempts
- [x] Tested with special characters (`&`, `=`, `%`, `;`, etc.)
- [x] All 166 library tests passing

### 4. Add Bounded Input Validation Types (HIGH PRIORITY)
**Status**: ✅ COMPLETE (Breaking API Change)
**Files**: `src/app.rs`

- [x] Updated `Profile.name` to use `AppName` type
- [x] Updated `Profile.description` to use `Description` type
- [x] Updated `CreateApplicationProfile` struct
- [x] Updated `UpdateApplicationProfile` struct
- [x] Updated all tests to use validated types
- [x] All 166 library tests passing
- [x] Clippy checks passing

### 5. Implement Pagination Bounds Checking (HIGH PRIORITY)
**Status**: ✅ COMPLETE
**Files**: `src/validation.rs`, `src/app.rs`

- [x] Added library-wide validation functions (`validate_page_size`, `validate_page_number`)
- [x] Added `normalize()` method to `ApplicationQuery`
- [x] Validates page ≤ 10,000 and size ≤ 500
- [x] Sets default size to 50
- [x] Rejects size = 0
- [x] Updated `get_applications()` to call `normalize()`
- [x] All tests passing with bounds checking

---

## 🔴 HIGH PRIORITY - MOVED TO COMPLETED

### 3. Fix Query Parameter Injection
**Status**: ✅ COMPLETE
**Estimated Time**: 1-2 hours
**Files**: `src/app.rs` (lines 453-542)

**Current Problem**:
```rust
// VULNERABLE - No URL encoding
impl From<ApplicationQuery> for Vec<(String, String)> {
    fn from(query: ApplicationQuery) -> Self {
        let mut params = Vec::new();
        if let Some(name) = query.name {
            params.push(("name".to_string(), name));  // ❌ Not encoded
        }
        // ...
    }
}
```

**Task List**:
- [x] Add URL encoding functions to validation module
- [x] Update `ApplicationQuery::to_query_params()` to encode all values
- [x] Add unit tests for special characters (`&`, `=`, `%`, etc.)
- [x] Test with injection attempts: `"foo&admin=true"`
- [x] All tests passing

**Reference Code** (from review):
```rust
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};

// Helper to safely add parameter
let add_param = |params: &mut Vec<String>, key: &str, value: &str| {
    let encoded_value = utf8_percent_encode(value, NON_ALPHANUMERIC);
    params.push(format!("{}={}", key, encoded_value));
};
```

---

### 4. Add Bounded Input Validation Types
**Status**: ✅ COMPLETE
**Estimated Time**: 2-3 hours
**Files**: `src/app.rs`

**Current Problem**:
```rust
pub struct Profile {
    pub name: String,  // ❌ No validation
    pub description: Option<String>,  // ❌ Could be megabytes
    pub tags: Option<String>,  // ❌ Unbounded
}
```

**Task List**:
- [x] Update `Profile.name` to use `AppName` type
- [x] Update `Profile.description` to use `Description` type
- [x] Update `CreateApplicationProfile` struct
- [x] Update `UpdateApplicationProfile` struct
- [x] Add validation in constructors/builders
- [x] Update all tests to use validated types
- [x] All 166 library tests passing

**Breaking Change Warning**: This changes public API - requires semver bump

---

### 5. Implement Pagination Bounds Checking
**Status**: ✅ COMPLETE
**Estimated Time**: 1 hour
**Files**: `src/app.rs` (lines 376-400)

**Current Problem**:
```rust
pub struct ApplicationQuery {
    pub page: Option<u32>,
    pub size: Option<u32>,  // ❌ Could be u32::MAX!
}
```

**Task List**:
- [x] Add library-wide validation functions to validation module
- [x] Add `validate_page_size()` function
- [x] Add `validate_page_number()` function
- [x] Add `normalize()` method to `ApplicationQuery`
- [x] Validate `page` ≤ `MAX_PAGE_NUMBER` (10,000)
- [x] Validate `size` ≤ `MAX_PAGE_SIZE` (500)
- [x] Set default `size` to `DEFAULT_PAGE_SIZE` (50)
- [x] Reject `size` = 0
- [x] Update `get_applications()` to call `normalize()`
- [x] Add unit tests for bounds
- [x] All tests passing

**Reference Code**:
```rust
impl ApplicationQuery {
    pub fn normalize(self) -> Result<Self, ValidationError> {
        let size = match self.size {
            None => Some(DEFAULT_PAGE_SIZE),
            Some(0) => return Err(ValidationError::InvalidPageSize(0)),
            Some(s) if s > MAX_PAGE_SIZE => {
                log::warn!("Page size {} exceeds max {}, capping", s, MAX_PAGE_SIZE);
                Some(MAX_PAGE_SIZE)
            }
            Some(s) => Some(s),
        };
        // ... validate page too
        Ok(Self { page, size, ..self })
    }
}
```

---

### 6. Complete #[must_use] Annotations (LOW PRIORITY)
**Status**: ✅ COMPLETE
**Estimated Time**: 30 minutes
**Files**: `src/app.rs`, `src/validation.rs`

**Implementation Approach**:
- [x] Ran `cargo clippy -- -W clippy::must_use_candidate` to identify functions
- [x] Added `#[must_use = "reason"]` with descriptive messages to 11 functions
- [x] All 166 library tests passing
- [x] Zero clippy warnings

**Functions Annotated**:

**app.rs (5 builder methods)**:
- [x] `ApplicationQuery::new()` - "builder methods consume self and return modified Self"
- [x] `ApplicationQuery::with_name()` - "builder methods consume self and return modified Self"
- [x] `ApplicationQuery::with_policy_compliance()` - "builder methods consume self and return modified Self"
- [x] `ApplicationQuery::with_modified_after()` - "builder methods consume self and return modified Self"
- [x] `ApplicationQuery::with_modified_before()` - "builder methods consume self and return modified Self"

**validation.rs (6 functions)**:
- [x] `AppGuid::as_str()` - "this method returns the inner value without modifying the type"
- [x] `AppGuid::as_url_safe()` - "this method returns the inner value without modifying the type"
- [x] `AppName::as_str()` - "this method returns the inner value without modifying the type"
- [x] `Description::as_str()` - "this method returns the inner value without modifying the type"
- [x] `encode_query_param()` - "this function performs URL encoding and returns the encoded value"
- [x] `build_query_param()` - "this function builds and returns a query parameter tuple"

**Note**: Clippy did NOT recommend adding `#[must_use]` to async getter functions like `get_all_applications()`. This is by design - Clippy is conservative with async functions. The original checklist suggested these, but following Clippy's guidance is the safer approach.

---

### 7. Enhance KMS Alias Validation (MEDIUM PRIORITY)
**Status**: ✅ COMPLETE (Reviewed and Approved)
**Completion Date**: 2025-11-07

**Decision**: Current validation is sufficient. The existing `validate_kms_alias()` function (lines 1400-1433) is comprehensive:
- [x] Validates `alias/` prefix
- [x] Checks length (8-256 characters)
- [x] Rejects AWS reserved names (`aws` prefix/suffix)
- [x] Validates character set (alphanumeric, `-`, `_`, `/`)
- [x] Prevents empty alias names

**Deferred Enhancements** (only if needed):
- Multi-region ARN format support
- `KmsAlias` newtype wrapper
- Additional AWS-specific validation rules

---

### 8. Add Custom Debug Implementations (MEDIUM PRIORITY)
**Status**: ✅ COMPLETE
**Completion Date**: 2025-11-07
**Files**: `src/app.rs`

**Implementation**:
- [x] Added `use std::fmt` import
- [x] Removed `#[derive(Debug)]` from `BusinessOwner`
- [x] Implemented custom `Debug` for `BusinessOwner` that redacts email and name
- [x] Removed `#[derive(Debug)]` from `CustomField`
- [x] Implemented custom `Debug` for `CustomField` that redacts value
- [x] Added security documentation to both structs
- [x] All 166 library tests passing
- [x] Zero clippy warnings

**Implemented Code**:
```rust
impl fmt::Debug for BusinessOwner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BusinessOwner")
            .field("email", &"[REDACTED]")
            .field("name", &"[REDACTED]")
            .finish()
    }
}

impl fmt::Debug for CustomField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CustomField")
            .field("name", &self.name)
            .field("value", &"[REDACTED]")
            .finish()
    }
}
```

**Impact**: Prevents accidental PII logging in error messages and debug output.

---

### 9. Improve Error Context (MEDIUM PRIORITY)
**Status**: ✅ COMPLETE
**Completion Date**: 2025-11-07
**Files**: `src/client.rs`, `src/app.rs`

**Implementation**:
- [x] Updated `handle_response()` to accept `context: &str` parameter
- [x] Enhanced error messages to include operation context and URL
- [x] Updated all 9 call sites with meaningful context strings:
  - `client.rs`: 4 wrapper functions (GET, POST, PUT, DELETE)
  - `app.rs`: 5 application methods (list, get, create, update, delete)
- [x] All 166 library tests passing
- [x] Zero clippy warnings

**Implemented Signature**:
```rust
pub async fn handle_response(
    response: reqwest::Response,
    context: &str,
) -> Result<reqwest::Response, VeracodeError> {
    if !response.status().is_success() {
        let status = response.status();
        let url = response.url().clone();
        let error_text = response.text().await?;
        return Err(VeracodeError::InvalidResponse(format!(
            "Failed to {context}\n  URL: {url}\n  HTTP {status}: {error_text}"
        )));
    }
    Ok(response)
}
```

**Example Error Output**:
```
Error: Failed to get application details
  URL: https://api.veracode.com/appsec/v1/applications/123-456-789
  HTTP 404: {"error": "Application not found"}
```

**Impact**: Dramatically improves debugging experience and error reporting.

---

## 🟢 LOW PRIORITY

### 10. Update Tests for New Validation Types
**Status**: 📋 TODO
**Estimated Time**: 2-3 hours
**Files**: `src/app.rs` (tests), integration tests

**Task List**:
- [ ] Update unit tests to create `AppGuid` instead of `String`
- [ ] Add validation error tests
- [ ] Test that invalid GUIDs are rejected
- [ ] Update integration tests if they exist
- [ ] Add property-based tests (optional, using `proptest`)
- [ ] Ensure all tests pass with `cargo test`

---

## Additional Recommendations (Future Work)

### Rate Limiting (Client-Side)
- Add request throttling to prevent API abuse
- Implement exponential backoff
- Add configurable rate limits

### Timeout Configuration
- Already partially implemented in `lib.rs`
- Ensure all operations respect timeouts
- Add per-operation timeout overrides

### Audit Logging
- Log security-sensitive operations
- Include user/API key identifier (hashed)
- Timestamp all operations
- Add structured logging with `tracing` crate

### Fuzzing
- Add fuzzing targets for validators
- Fuzz `AppGuid::new()`
- Fuzz `ApplicationQuery` parsing
- Fuzz KMS alias validation

---

## How to Use This Checklist

1. **Pick a task** - Start with HIGH priority items
2. **Create a branch** - `git checkout -b fix/query-parameter-injection`
3. **Implement the fix** - Follow the task list for that item
4. **Run tests** - `cargo test`
5. **Run clippy** - `cargo clippy`
6. **Commit** - Use descriptive commit messages
7. **Mark complete** - Update this file with `[x]`
8. **Move to next task**

## Testing Commands

```bash
# Run all tests
cargo test --package veracode-platform

# Run tests with output
cargo test --package veracode-platform -- --nocapture

# Run specific test
cargo test --package veracode-platform test_app_guid_valid

# Run clippy
cargo clippy --package veracode-platform

# Run with defensive lints
cargo clippy --package veracode-platform -- \
    -D clippy::indexing_slicing \
    -D clippy::unwrap_used \
    -D clippy::expect_used \
    -D clippy::panic

# Build documentation
cargo doc --package veracode-platform --open
```

## References

- Original review: `.claude/defensive-code-reviewer.md` (if exists)
- Validation module: `src/validation.rs`
- Main implementation: `src/app.rs`
- OWASP Top 10: https://owasp.org/www-project-top-ten/
- Rust secure coding: https://anssi-fr.github.io/rust-guide/

---

Last Updated: 2025-11-07
Review Date: 2025-11-07 (Tasks #7, #8, #9: KMS Validation Review, Custom Debug, Error Context)
