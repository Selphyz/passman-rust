use rand::Rng;

const UPPERCASE_CHARS: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWERCASE_CHARS: &str = "abcdefghijklmnopqrstuvwxyz";
const NUMBER_CHARS: &str = "0123456789";
const SYMBOL_CHARS: &str = "!@#$%^&*()_+-=[]{}|;:,.<>?";

pub fn generate_password(uppercase: bool, lowercase: bool, numbers: bool, symbols: bool, all: bool, length: usize) -> String {
    let mut char_set = String::new();

    if all || uppercase {
        char_set.push_str(UPPERCASE_CHARS);
    }
    if all || lowercase {
        char_set.push_str(LOWERCASE_CHARS);
    }
    if all || numbers {
        char_set.push_str(NUMBER_CHARS);
    }
    if all || symbols {
        char_set.push_str(SYMBOL_CHARS);
    }

    if char_set.is_empty() {
        char_set.push_str(LOWERCASE_CHARS); // Default to lowercase if nothing is selected
    }

    let mut rng = rand::thread_rng();
    (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..char_set.len());
            char_set.chars().nth(idx).unwrap()
        })
        .collect()
}