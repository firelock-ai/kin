// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use super::*;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

fn emit(root: &Path, operation: OperationId) {
    notify(root, operation, Hash256::from_bytes([7; 32]), "test-digest");
}

#[test]
fn observer_matches_exact_root_operation_and_blocking_thread_only() {
    let root = std::env::temp_dir().join("kin-observer-fixture");
    let operation = OperationId::new();
    let count = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&count);
    let guard = observe(root.clone(), operation, move |_| {
        seen.fetch_add(1, Ordering::SeqCst);
    })
    .unwrap();
    assert!(matches!(
        observe(root.clone(), operation, |_| {}),
        Err(RegistrationError::AlreadyRegisteredOnThread)
    ));
    emit(&root.join("different"), operation);
    emit(&root, OperationId::new());
    let other_root = root.clone();
    std::thread::spawn(move || emit(&other_root, operation))
        .join()
        .unwrap();
    assert_eq!(count.load(Ordering::SeqCst), 0);
    emit(&root, operation);
    assert_eq!(count.load(Ordering::SeqCst), 1);
    drop(guard);
    emit(&root, operation);
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

#[test]
fn observer_unwind_unregisters_and_callback_has_no_tls_borrow() {
    let root = std::env::temp_dir().join("kin-observer-unwind");
    let operation = OperationId::new();
    let captured = root.clone();
    let result = std::panic::catch_unwind(|| {
        let _guard = observe(root.clone(), operation, move |_| {
            // This reaches an intentional error rather than RefCell recursion.
            assert!(matches!(
                observe(captured.clone(), operation, |_| {}),
                Err(RegistrationError::AlreadyRegisteredOnThread)
            ));
            panic!("controlled observer unwind");
        })
        .unwrap();
        emit(&root, operation);
    });
    assert!(result.is_err());
    let _replacement = observe(root, operation, |_| {}).unwrap();
    assert!(matches!(
        observe(PathBuf::from("relative"), operation, |_| {}),
        Err(RegistrationError::RootMustBeAbsolute)
    ));
}
