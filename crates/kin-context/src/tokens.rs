/// Estimate token count from text.
///
/// Uses a simple heuristic: ~4 characters per token (typical for code).
pub fn estimate_tokens(text: &str) -> usize {
    (text.len() + 3) / 4
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_string_is_zero_tokens() {
        assert_eq!(estimate_tokens(""), 0);
    }

    #[test]
    fn short_string() {
        let tokens = estimate_tokens("fn foo()");
        assert!(tokens > 0 && tokens <= 3);
    }

    #[test]
    fn longer_string() {
        let text = "fn process_payment(amount: f64, currency: &str) -> Result<Receipt, PaymentError>";
        let tokens = estimate_tokens(text);
        assert!(tokens >= 15 && tokens <= 25);
    }
}
