#!/bin/bash

# Test script to verify that --create-gitlab-issues works independently of --export-findings

echo "🧪 Testing Independent GitLab Issues Creation"
echo "============================================="

# Set GitLab environment variables
export PRIVATE_TOKEN="glpat-nMtpRxeXPtsDzFDFxHWk"
export CI_PROJECT_ID="1" 
export GITLAB_URL="http://jupiter.hell.local:8929/api/v4/projects/"

echo "✅ Environment variables set:"
echo "   PRIVATE_TOKEN: ${PRIVATE_TOKEN:0:10}..."
echo "   CI_PROJECT_ID: $CI_PROJECT_ID"
echo "   GITLAB_URL: $GITLAB_URL"

echo ""
echo "🚀 Testing --create-gitlab-issues WITHOUT --export-findings"
echo "==========================================================="

# This should work now - GitLab issues creation without export
echo "Command: ./target/release/verascan --pipeline-scan --create-gitlab-issues --filepath /some/test/path --filefilter '*.jar'"
echo ""
echo "Expected behavior:"
echo "  ✅ Should create GitLab issues independently"
echo "  ✅ Should NOT require --export-findings"
echo "  ✅ Should see: '🔗 Creating GitLab issues from scan findings...'"
echo ""
echo "Note: This is just a demonstration of the command."
echo "To actually run it, you would need valid Java files to scan."
echo ""
echo "Example usage:"
echo "./target/release/verascan \\"
echo "    --filepath /path/to/your/java/project \\"
echo "    --filefilter '*.jar,*.war,*.zip' \\"
echo "    --pipeline-scan \\"
echo "    --project-name 'My Application' \\"
echo "    --create-gitlab-issues \\"
echo "    --debug"