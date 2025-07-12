# GitLab Issues Integration Guide

This guide shows how to use Verascan's GitLab issues integration to automatically create issue tickets from Veracode pipeline scan findings.

## Overview

The GitLab issues integration automatically creates GitLab issue tickets for security vulnerabilities found during Veracode pipeline scans. Each issue includes:

- **Severity-based labeling** (security::severity::high, security::cwe-79, etc.)
- **Detailed vulnerability information** with CWE references
- **Source code links** (when running in GitLab CI)
- **Remediation guidance**
- **Pipeline run links**

## Quick Start

### 1. Set Required Environment Variables

```bash
# GitLab API token (required)
export PRIVATE_TOKEN="glpat-your-gitlab-token-here"

# GitLab project ID (required), needs developer role and api scope
export CI_PROJECT_ID="12345"

# Optional: GitLab URL (defaults to gitlab.com)
export GITLAB_URL="https://gitlab.com/api/v4/projects/"
```

### 2. Run Verascan with GitLab Integration

```bash
./verascan \
    --filepath /path/to/your/project \
    --filefilter "*.jar,*.war,*.zip" \
    --pipeline-scan \
    --project-name "My Application" \
    --create-gitlab-issues \
    --show-findings \
    --debug
```

## Environment Variables

### Required Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `PRIVATE_TOKEN` | GitLab personal access token or project token | `glpat-xxxxxxxxxxxxxxxxxxxx` |
| `CI_PROJECT_ID` | GitLab project ID (numeric) | `12345` |

### Optional Variables

| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| `GITLAB_URL` | GitLab API base URL | `https://gitlab.com/api/v4/projects/` | `https://gitlab.company.com/api/v4/projects/` |
| `CI_PIPELINE_ID` | Current pipeline ID (auto-set in GitLab CI) | None | `67890` |
| `CI_PROJECT_URL` | Project web URL (auto-set in GitLab CI) | None | `https://gitlab.com/user/project` |
| `CI_COMMIT_SHA` | Current commit SHA (auto-set in GitLab CI) | None | `abc123def456` |

### Alternative Token Variables

The integration supports multiple token variable names:
- `PRIVATE_TOKEN` (recommended)
- `CI_TOKEN` 
- `GITLAB_TOKEN`

## GitLab CI Integration

### Complete .gitlab-ci.yml Example

```yaml
stages:
  - security-scan

veracode-security-scan:
  stage: security-scan
  image: rust:latest
  
  before_script:
    - cargo build --release
    
  script:
    - ./target/release/verascan
        --filepath "${CI_PROJECT_DIR}"
        --filefilter "*.jar,*.war,*.zip"
        --pipeline-scan
        --project-name "${CI_PROJECT_NAME}"
        --create-gitlab-issues
        --export-findings "security-report.json"
        --export-format "gitlab"
        --show-findings
        --min-severity "medium"
  
  # Environment variables
  variables:
    GITLAB_URL: "https://gitlab.com/api/v4/projects/"
    # CI_TOKEN, CI_PROJECT_ID, etc. are automatically available
  
  artifacts:
    reports:
      sast: security-report.json
    expire_in: 30 days
  
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
    - if: $CI_MERGE_REQUEST_ID
```

## GitLab Token Setup

### Option 1: Personal Access Token

1. Go to GitLab → Settings → Access Tokens
2. Create token with `api` scope
3. Copy token and set as `PRIVATE_TOKEN` environment variable

### Option 2: Project Access Token

1. Go to Project → Settings → Access Tokens  
2. Create token with `api` scope
3. Copy token and set as `PRIVATE_TOKEN` environment variable

### Option 3: CI/CD Variables

1. Go to Project → Settings → CI/CD → Variables
2. Add variable `PRIVATE_TOKEN` with your token value
3. Mark as masked and protected

## Issue Creation Behavior

### What Gets Created

- **One issue per unique vulnerability** found in the scan
- **Severity filtering**: Informational findings (severity 0) are skipped by default
- **Rich descriptions** with vulnerability details, file locations, and remediation steps
- **Automatic labeling** based on severity and vulnerability type

### Issue Labels

The integration automatically adds labels:
- `security::veracode` - All Veracode findings
- `security::sast` - Static analysis findings  
- `security::severity::high` - Based on finding severity
- `security::cwe-79` - Based on CWE ID (when available)
- `priority::high` - For critical/high severity findings

### Example Issue Content

```markdown
## Security Vulnerability: Cross-Site Scripting vulnerability

![High](https://img.shields.io/badge/Severity-High-important)

### Details

| Field | Value |
|-------|-------|
| **Issue Type** | Cross-Site Scripting |
| **Severity** | High (4) |
| **CWE** | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) |
| **File** | `src/main/webapp/input.jsp` |
| **Line** | 42 |
| **Function** | `processInput` |
| **Scan ID** | `scan-12345` |
| **Project** | My Application |

### 📁 Source Code

[View in repository](https://gitlab.com/user/project/blob/abc123/src/main/webapp/input.jsp#L42)

### 🔗 Related Links

- [Pipeline Run](https://gitlab.com/user/project/-/pipelines/67890)

### 🔧 Remediation

This Cross-Site Scripting vulnerability requires attention. Please review the identified code and apply appropriate security measures:

1. **Review** the vulnerable code in the identified file and function
2. **Research** the specific vulnerability type and remediation techniques  
3. **Apply** security fixes following secure coding practices
4. **Test** thoroughly to ensure the fix doesn't break functionality
5. **Re-scan** to verify the vulnerability has been resolved

For detailed information about this vulnerability type, see [CWE-79](https://cwe.mitre.org/data/definitions/79.html).

---

*This issue was automatically created by Verascan security scanning.*
```

## Manual Testing

Use the provided example script to test the integration:

```bash
# Set environment variables
export PRIVATE_TOKEN="your-token"
export CI_PROJECT_ID="12345"

# Run the example
chmod +x examples/gitlab_issues_example.sh
./examples/gitlab_issues_example.sh
```

Or run the manual test example:

```bash
cargo run --example manual_test_example
```

## Troubleshooting

### Common Issues

**"Missing environment variable" error**
- Ensure `PRIVATE_TOKEN` and `CI_PROJECT_ID` are set
- Check token has `api` scope permissions

**"GitLab API error: 401"**  
- Token may be expired or invalid
- Verify token has access to the specified project

**"GitLab API error: 404"**
- Check `CI_PROJECT_ID` is correct (numeric project ID)
- Verify project exists and token has access

**"GitLab API error: 403"**
- Token lacks sufficient permissions
- Ensure token has `api` scope and project access

### Debug Mode

Enable debug mode to see detailed API requests:

```bash
./verascan --create-gitlab-issues --debug ...
```

This will show:
- GitLab client initialization details
- API request URLs  
- Issue creation progress
- API response details

## Integration Examples

See the `examples/` directory for:
- `gitlab_issues_example.sh` - Bash script example
- `gitlab_ci_example.yml` - Complete GitLab CI configuration
- `manual_test_example.rs` - Rust code for manual testing

## Support

For issues or questions:
1. Check the troubleshooting section above
2. Enable debug mode for detailed logging
3. Verify environment variables and GitLab permissions
4. Check GitLab project issue tracker for existing issues