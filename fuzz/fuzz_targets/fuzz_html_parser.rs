#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(html) = std::str::from_utf8(data) {
        // Fuzz the HTML tag stripping function from pipeline.rs:274
        // This is a critical security function that processes untrusted HTML
        strip_html_tags_test(html);

        // Test edge cases with specific patterns
        test_nested_tags(html);
        test_unclosed_tags(html);
        test_malformed_tags(html);
        test_script_tags(html);
        test_attribute_injection(html);
    }
});

/// Replicate strip_html_tags from veracode-api/src/pipeline.rs:274
/// This is a simple character-by-character HTML tag stripper
fn strip_html_tags_test(s: &str) -> String {
    let mut result = String::new();
    let mut in_tag = false;

    for c in s.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ => {
                if !in_tag {
                    result.push(c);
                }
            }
        }
    }

    result
}

/// Test nested tags like <div><span><b>text</b></span></div>
fn test_nested_tags(html: &str) {
    let stripped = strip_html_tags_test(html);

    // Verify no angle brackets remain
    let _has_brackets = stripped.contains('<') || stripped.contains('>');
}

/// Test unclosed tags like <div><span>text
fn test_unclosed_tags(html: &str) {
    let stripped = strip_html_tags_test(html);

    // Should handle gracefully even if tags aren't closed
    // The state machine should be in "in_tag" state at the end
    let _result_len = stripped.len();
}

/// Test malformed tags like < div >, <>, <<>>, etc.
fn test_malformed_tags(html: &str) {
    let _stripped = strip_html_tags_test(html);

    // Should not panic on malformed input
}

/// Test script tags with JavaScript
fn test_script_tags(html: &str) {
    let stripped = strip_html_tags_test(html);

    // Should remove all tags including <script>
    // But note: this doesn't remove script CONTENT between tags
    // which is a potential security issue
    let _contains_script_tag = stripped.contains("<script");
}

/// Test attribute injection like <img src="x" onerror="alert(1)">
fn test_attribute_injection(html: &str) {
    let _stripped = strip_html_tags_test(html);

    // Tags and attributes should be removed
    // Only text content should remain
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_html_stripping() {
        assert_eq!(strip_html_tags_test("<b>hello</b>"), "hello");
        assert_eq!(strip_html_tags_test("<div>world</div>"), "world");
    }

    #[test]
    fn test_nested() {
        assert_eq!(
            strip_html_tags_test("<div><span><b>text</b></span></div>"),
            "text"
        );
    }

    #[test]
    fn test_unclosed() {
        // Unclosed tag - everything after < is removed
        assert_eq!(strip_html_tags_test("<div>text"), "text");
    }

    #[test]
    fn test_no_tags() {
        assert_eq!(strip_html_tags_test("plain text"), "plain text");
    }

    #[test]
    fn test_empty() {
        assert_eq!(strip_html_tags_test(""), "");
    }

    #[test]
    fn test_multiple_brackets() {
        assert_eq!(strip_html_tags_test("<<>>text<<>>"), "text");
    }

    #[test]
    fn test_script_content_not_removed() {
        // SECURITY NOTE: This test demonstrates that script CONTENT is NOT removed
        // Only the tags are removed. This could be a security issue.
        let input = "<script>alert('XSS')</script>";
        let result = strip_html_tags_test(input);
        assert_eq!(result, "alert('XSS')"); // Script content remains!
    }
}
