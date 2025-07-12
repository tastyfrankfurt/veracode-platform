#!/bin/bash

# GitLab Issues Integration Example
# This script demonstrates how to use Verascan to create GitLab issues from pipeline scan results

echo "🔧 GitLab Issues Integration Example"
echo "===================================="

# Required Environment Variables for GitLab Integration
echo "Setting up GitLab environment variables..."

# GitLab API Token (required)
# You can get this from GitLab Settings > Access Tokens
export PRIVATE_TOKEN="your-gitlab-api-token-here"
# Alternative: export CI_TOKEN="your-gitlab-api-token-here"

# GitLab Project ID (required)
# Found in your GitLab project settings page
export CI_PROJECT_ID="12345"

# GitLab URL (optional, defaults to gitlab.com)
export GITLAB_URL="https://gitlab.com/api/v4/projects/"
# For self-hosted GitLab: export GITLAB_URL="https://your-gitlab.company.com/api/v4/projects/"

# Optional CI/CD Variables (automatically set in GitLab CI, but can be set manually for testing)
export CI_PIPELINE_ID="67890"
export CI_PROJECT_URL="https://gitlab.com/your-username/your-project"
export CI_COMMIT_SHA="abc123def456"

echo "✅ Environment variables configured:"
echo "   PRIVATE_TOKEN: ${PRIVATE_TOKEN:0:8}..."
echo "   CI_PROJECT_ID: $CI_PROJECT_ID"
echo "   GITLAB_URL: $GITLAB_URL"
echo "   CI_PIPELINE_ID: $CI_PIPELINE_ID"
echo "   CI_PROJECT_URL: $CI_PROJECT_URL"
echo "   CI_COMMIT_SHA: $CI_COMMIT_SHA"

echo ""
echo "🚀 Running Verascan with GitLab Issues Integration"
echo "=================================================="

# Example command to run pipeline scan with GitLab issues creation
# Replace the filepath and filefilter with your actual project paths
./target/release/verascan \
    --filepath /path/to/your/project \
    --filefilter "*.jar,*.war,*.zip" \
    --pipeline-scan \
    --project-name "Your Project Name" \
    --create-gitlab-issues \
    --export-findings scan-results.json \
    --show-findings \
    --debug

echo ""
echo "✅ Scan completed! Check your GitLab project for new security issue tickets."
echo "   Issues will be created with:"
echo "   - Severity labels (security::severity::high, etc.)"
echo "   - CWE references and links"
echo "   - File and line number information"
echo "   - Links back to your pipeline run"
echo "   - Detailed remediation guidance"