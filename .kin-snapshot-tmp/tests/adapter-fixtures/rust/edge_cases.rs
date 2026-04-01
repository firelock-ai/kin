// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

// Fixture: Rust edge cases
// Tests: trait impls, derive macros, generics, lifetimes, enum variants,
// closures, async, nested modules, where clauses, const generics

use std::collections::HashMap;
use std::fmt;

/// A generic container with a trait bound.
pub struct Container<T: Clone + fmt::Display> {
    items: Vec<T>,
    label: String,
}

impl<T: Clone + fmt::Display> Container<T> {
    pub fn new(label: &str) -> Self {
        Self {
            items: Vec::new(),
            label: label.to_string(),
        }
    }

    pub fn push(&mut self, item: T) {
        self.items.push(item);
    }

    pub fn first(&self) -> Option<&T> {
        self.items.first()
    }
}

/// Display impl for Container.
impl<T: Clone + fmt::Display> fmt::Display for Container<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Container({}): {} items", self.label, self.items.len())
    }
}

/// An enum with data variants.
pub enum Shape {
    Circle { radius: f64 },
    Rectangle { width: f64, height: f64 },
    Triangle(f64, f64, f64),
}

impl Shape {
    pub fn area(&self) -> f64 {
        match self {
            Shape::Circle { radius } => std::f64::consts::PI * radius * radius,
            Shape::Rectangle { width, height } => width * height,
            Shape::Triangle(a, b, c) => {
                let s = (a + b + c) / 2.0;
                (s * (s - a) * (s - b) * (s - c)).sqrt()
            }
        }
    }
}

/// Trait with associated type and default method.
pub trait Processor {
    type Output;
    type Error;

    fn process(&self, input: &str) -> Result<Self::Output, Self::Error>;

    fn name(&self) -> &str {
        "unnamed"
    }
}

/// Function with lifetime parameters.
pub fn longest<'a>(x: &'a str, y: &'a str) -> &'a str {
    if x.len() > y.len() { x } else { y }
}

/// Function with where clause.
pub fn serialize_map<K, V>(map: &HashMap<K, V>) -> String
where
    K: fmt::Display,
    V: fmt::Display,
{
    map.iter()
        .map(|(k, v)| format!("{}: {}", k, v))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Async function.
pub async fn fetch_data(url: &str) -> Result<String, Box<dyn std::error::Error>> {
    Ok(format!("data from {}", url))
}

/// Constant with type annotation.
pub const MAX_RETRIES: u32 = 3;

/// Static mutable (unsafe).
pub static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Nested module.
pub mod utils {
    pub fn helper() -> bool {
        true
    }
}

/// Type alias with generics.
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn container_works() {
        let mut c = Container::new("test");
        c.push(42);
        assert_eq!(c.first(), Some(&42));
    }

    #[test]
    fn shape_area() {
        let circle = Shape::Circle { radius: 1.0 };
        assert!((circle.area() - std::f64::consts::PI).abs() < 1e-10);
    }
}
