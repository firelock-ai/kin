// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! macOS Quality-of-Service thread hints.
//!
//! Tags the calling thread with `QOS_CLASS_USER_INITIATED`, biasing the
//! scheduler toward performance cores for inference work. No-op on other
//! platforms.

/// Raises the calling thread's QoS to `QOS_CLASS_USER_INITIATED` on macOS.
#[cfg(target_os = "macos")]
pub fn set_thread_qos_user_initiated() {
    // SAFETY: `pthread_set_qos_class_self_np` mutates only the calling thread's
    // QoS attributes and has no preconditions beyond a valid `qos_class_t`.
    unsafe {
        libc::pthread_set_qos_class_self_np(libc::qos_class_t::QOS_CLASS_USER_INITIATED, 0);
    }
}

/// No-op on non-macOS targets.
#[cfg(not(target_os = "macos"))]
pub fn set_thread_qos_user_initiated() {}
