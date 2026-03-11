// Fixture: basic Rust entities
// Expected: 2 functions, 1 struct, 1 impl block

pub struct UserProfile {
    pub name: String,
    pub email: String,
}

impl UserProfile {
    pub fn new(name: String, email: String) -> Self {
        Self { name, email }
    }
}

pub fn create_user(name: &str, email: &str) -> UserProfile {
    UserProfile::new(name.to_string(), email.to_string())
}

fn helper_internal() -> u32 {
    42
}
