// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Wheel file names and platform compatibility tags.
//!
//! A locked version usually has several wheels, one per interpreter and
//! platform. The analysis environment takes the one an installer would take
//! for the pinned CPython on this machine, in the order `packaging.tags`
//! prefers: an interpreter-specific wheel for this platform, then a stable-ABI
//! one, then a pure-Python one for this platform, then a pure-Python `any`.

/// A parsed wheel file name,
/// `{name}-{version}(-{build})?-{python}-{abi}-{platform}.whl`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WheelName {
    pub name: String,
    pub version: String,
    /// Every `(python, abi, platform)` triple the compressed tag set names.
    pub tags: Vec<(String, String, String)>,
}

/// Parse a wheel file name; `None` for anything that is not one.
pub fn parse_wheel_filename(filename: &str) -> Option<WheelName> {
    let stem = filename.strip_suffix(".whl")?;
    let parts: Vec<&str> = stem.split('-').collect();
    if !(parts.len() == 5 || parts.len() == 6) {
        return None;
    }
    let (python, abi, platform) = (
        parts[parts.len() - 3],
        parts[parts.len() - 2],
        parts[parts.len() - 1],
    );
    let mut tags = Vec::new();
    for python in python.split('.') {
        for abi in abi.split('.') {
            for platform in platform.split('.') {
                tags.push((
                    python.to_ascii_lowercase(),
                    abi.to_ascii_lowercase(),
                    platform.to_ascii_lowercase(),
                ));
            }
        }
    }
    Some(WheelName {
        name: parts[0].to_string(),
        version: parts[1].to_string(),
        tags,
    })
}

/// The version an sdist's file name carries, for `{name}-{version}.tar.gz`
/// or `.zip`, given the package's normalized name.
pub fn sdist_version(filename: &str, normalized_name: &str) -> Option<String> {
    let stem = filename
        .strip_suffix(".tar.gz")
        .or_else(|| filename.strip_suffix(".zip"))?;
    // The name part may itself hold dashes; the version is what follows the
    // name once both are normalized.
    let lowered = stem.to_ascii_lowercase().replace(['_', '.'], "-");
    let prefix = format!("{normalized_name}-");
    lowered
        .starts_with(&prefix)
        .then(|| stem[prefix.len()..].to_string())
}

/// An operating system a wheel can target, with the version the host runs
/// when it is known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    /// macOS, with its `(major, minor)` version.
    Mac(Option<(u32, u32)>),
    /// Linux, with the glibc version for a glibc host, or the musl version for
    /// a musl host.
    Linux {
        glibc: Option<(u32, u32)>,
        musl: Option<(u32, u32)>,
    },
    Windows,
}

/// The platform wheels are chosen for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Platform {
    pub os: Os,
    /// Rust's spelling: `aarch64`, `x86_64`.
    pub arch: &'static str,
}

impl Platform {
    /// This host.
    pub fn host() -> Self {
        let os = match std::env::consts::OS {
            "macos" => Os::Mac(host_macos_version()),
            "windows" => Os::Windows,
            _ => Os::Linux {
                glibc: host_glibc_version(),
                musl: cfg!(target_env = "musl").then_some((1, 2)),
            },
        };
        let arch = match std::env::consts::ARCH {
            "aarch64" => "aarch64",
            "x86_64" => "x86_64",
            "x86" => "i686",
            other => other,
        };
        Self { os, arch }
    }

    /// A short, stable name for an environment's identity. The OS version
    /// is left out so an OS update does not rename every environment.
    pub fn id(&self) -> String {
        let os = match self.os {
            Os::Mac(_) => "macos",
            Os::Linux { musl: Some(_), .. } => "linux-musl",
            Os::Linux { .. } => "linux",
            Os::Windows => "windows",
        };
        format!("{os}-{}", self.arch)
    }

    /// Rust's target triple for this platform, as `uv --python-platform` and
    /// the standalone CPython builds name it.
    pub fn triple(&self) -> Option<&'static str> {
        Some(match (self.os, self.arch) {
            (Os::Mac(_), "aarch64") => "aarch64-apple-darwin",
            (Os::Mac(_), "x86_64") => "x86_64-apple-darwin",
            (Os::Linux { musl: None, .. }, "x86_64") => "x86_64-unknown-linux-gnu",
            (Os::Linux { musl: None, .. }, "aarch64") => "aarch64-unknown-linux-gnu",
            _ => return None,
        })
    }

    /// The rank of a platform tag on this platform, lower preferred, or
    /// `None` when a wheel for it cannot run here. `any` is not a platform tag.
    fn rank(&self, tag: &str) -> Option<u32> {
        match self.os {
            Os::Mac(version) => {
                let rest = tag.strip_prefix("macosx_")?;
                let mut parts = rest.splitn(3, '_');
                let major: u32 = parts.next()?.parse().ok()?;
                let minor: u32 = parts.next()?.parse().ok()?;
                let arch = parts.next()?;
                let arch_rank = match self.arch {
                    "aarch64" => ["arm64", "universal2"].iter().position(|a| *a == arch)?,
                    "x86_64" => [
                        "x86_64",
                        "intel",
                        "fat64",
                        "fat3",
                        "universal2",
                        "universal",
                    ]
                    .iter()
                    .position(|a| *a == arch)?,
                    _ => return None,
                } as u32;
                if version.is_some_and(|host| (major, minor) > host) {
                    return None;
                }
                // Newer deployment targets first, as an installer prefers.
                Some((100 - major.min(99)) * 1_000 + (100 - minor.min(99)) * 10 + arch_rank)
            }
            Os::Linux { glibc, musl } => {
                let (family, rest) = if let Some(rest) = tag.strip_prefix("manylinux_") {
                    ("glibc", rest.to_string())
                } else if let Some(rest) = tag.strip_prefix("musllinux_") {
                    ("musl", rest.to_string())
                } else if let Some(arch) = tag.strip_prefix("manylinux2014_") {
                    ("glibc", format!("2_17_{arch}"))
                } else if let Some(arch) = tag.strip_prefix("manylinux2010_") {
                    ("glibc", format!("2_12_{arch}"))
                } else if let Some(arch) = tag.strip_prefix("manylinux1_") {
                    ("glibc", format!("2_5_{arch}"))
                } else if let Some(arch) = tag.strip_prefix("linux_") {
                    return (arch == self.arch).then_some(999_999);
                } else {
                    return None;
                };
                let mut parts = rest.splitn(3, '_');
                let major: u32 = parts.next()?.parse().ok()?;
                let minor: u32 = parts.next()?.parse().ok()?;
                if parts.next()? != self.arch {
                    return None;
                }
                let host = match family {
                    "glibc" if musl.is_none() => glibc,
                    "musl" if musl.is_some() => musl,
                    _ => return None,
                };
                if host.is_some_and(|host| (major, minor) > host) {
                    return None;
                }
                Some((100 - major.min(99)) * 1_000 + (100 - minor.min(99)))
            }
            Os::Windows => {
                let arch = match self.arch {
                    "x86_64" => "win_amd64",
                    "aarch64" => "win_arm64",
                    _ => "win32",
                };
                (tag == arch).then_some(0)
            }
        }
    }
}

/// The macOS version this host runs, from `kern.osproductversion`.
#[cfg(target_os = "macos")]
fn host_macos_version() -> Option<(u32, u32)> {
    let name = std::ffi::CString::new("kern.osproductversion").ok()?;
    let mut buffer = [0u8; 64];
    let mut length = buffer.len();
    // SAFETY: the name is NUL-terminated, the buffer and its length describe
    // writable memory, and no new value is set.
    let status = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            buffer.as_mut_ptr().cast(),
            &mut length,
            std::ptr::null_mut(),
            0,
        )
    };
    if status != 0 {
        return None;
    }
    let text = std::str::from_utf8(&buffer[..length]).ok()?;
    let mut parts = text.trim_end_matches('\0').split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts
        .next()
        .and_then(|minor| minor.parse().ok())
        .unwrap_or(0);
    Some((major, minor))
}

#[cfg(not(target_os = "macos"))]
fn host_macos_version() -> Option<(u32, u32)> {
    None
}

/// The glibc version this host runs.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn host_glibc_version() -> Option<(u32, u32)> {
    // SAFETY: gnu_get_libc_version returns a pointer to a static string.
    let version = unsafe { std::ffi::CStr::from_ptr(libc::gnu_get_libc_version()) };
    let mut parts = version.to_str().ok()?.split('.');
    Some((parts.next()?.parse().ok()?, parts.next()?.parse().ok()?))
}

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
fn host_glibc_version() -> Option<(u32, u32)> {
    None
}

/// A CPython minor version on a platform, which is what a wheel must suit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WheelTarget {
    /// The minor version of Python 3: 11 for 3.11.
    pub minor: u32,
    pub platform: Platform,
}

impl WheelTarget {
    /// The rank of one `(python, abi, platform)` tag, lower preferred, or
    /// `None` when it does not suit this target.
    fn tag_rank(&self, python: &str, abi: &str, platform: &str) -> Option<(u32, u32, u32)> {
        let minor = self.minor;
        let own = format!("cp3{minor}");
        let python_minor = |prefix: &str| -> Option<u32> {
            python.strip_prefix(prefix)?.strip_prefix('3')?.parse().ok()
        };
        if platform == "any" {
            let rank = if python == own && abi == "none" {
                0
            } else if abi != "none" {
                return None;
            } else if python == format!("py3{minor}") {
                1
            } else if python == "py3" {
                2
            } else {
                let older = python_minor("py").filter(|older| *older < minor)?;
                2 + (minor - older)
            };
            return Some((2, rank, 0));
        }
        let platform_rank = self.platform.rank(platform)?;
        if python.starts_with("cp") {
            let rank = if python == own && abi == own {
                0
            } else if python == own && abi == "abi3" {
                1
            } else if python == own && abi == "none" {
                2
            } else if abi == "abi3" {
                let older = python_minor("cp").filter(|older| *older < minor)?;
                2 + (minor - older)
            } else {
                return None;
            };
            return Some((0, rank, platform_rank));
        }
        if abi != "none" {
            return None;
        }
        let rank = if python == format!("py3{minor}") {
            0
        } else if python == "py3" {
            1
        } else {
            let older = python_minor("py").filter(|older| *older < minor)?;
            1 + (minor - older)
        };
        Some((1, rank, platform_rank))
    }

    /// The best rank any of a wheel's tags has here, or `None` when the wheel
    /// cannot be installed for this target.
    pub fn wheel_rank(&self, wheel: &WheelName) -> Option<(u32, u32, u32)> {
        wheel
            .tags
            .iter()
            .filter_map(|(python, abi, platform)| self.tag_rank(python, abi, platform))
            .min()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mac(minor: u32) -> WheelTarget {
        WheelTarget {
            minor,
            platform: Platform {
                os: Os::Mac(Some((15, 4))),
                arch: "aarch64",
            },
        }
    }

    fn linux(minor: u32) -> WheelTarget {
        WheelTarget {
            minor,
            platform: Platform {
                os: Os::Linux {
                    glibc: Some((2, 31)),
                    musl: None,
                },
                arch: "x86_64",
            },
        }
    }

    fn best<'a>(target: &WheelTarget, wheels: &[&'a str]) -> Option<&'a str> {
        wheels
            .iter()
            .filter_map(|file| {
                let rank = target.wheel_rank(&parse_wheel_filename(file)?)?;
                Some((rank, *file))
            })
            .min()
            .map(|(_, file)| file)
    }

    #[test]
    fn wheel_names_expand_compressed_tag_sets() {
        let wheel = parse_wheel_filename("six-1.16.0-py2.py3-none-any.whl").unwrap();
        assert_eq!(wheel.name, "six");
        assert_eq!(wheel.version, "1.16.0");
        assert_eq!(wheel.tags.len(), 2);
        let built = parse_wheel_filename(
            "pydantic_core-2.33.2-1-cp311-cp311-macosx_10_12_x86_64.macosx_11_0_arm64.whl",
        )
        .unwrap();
        assert_eq!(built.version, "2.33.2");
        assert_eq!(built.tags.len(), 2);
        assert!(parse_wheel_filename("requests-2.31.0.tar.gz").is_none());
        assert_eq!(
            sdist_version("PySocks-1.7.1.tar.gz", "pysocks").as_deref(),
            Some("1.7.1")
        );
        assert_eq!(
            sdist_version("zope.interface-6.0.zip", "zope-interface").as_deref(),
            Some("6.0")
        );
    }

    /// The pinned interpreter's own ABI wins over the stable ABI, which wins
    /// over a pure-Python wheel; a wheel for another interpreter, a newer
    /// macOS or another architecture is never taken.
    #[test]
    fn selection_follows_an_installers_preference() {
        let wheels = [
            "pkg-1.0-cp312-cp312-macosx_11_0_arm64.whl",
            "pkg-1.0-cp311-cp311-macosx_16_0_arm64.whl",
            "pkg-1.0-cp311-cp311-macosx_10_9_x86_64.whl",
            "pkg-1.0-cp38-abi3-macosx_11_0_arm64.whl",
            "pkg-1.0-py3-none-any.whl",
            "pkg-1.0-cp311-cp311-macosx_11_0_arm64.whl",
            "pkg-1.0-cp311-cp311-macosx_10_9_universal2.whl",
        ];
        assert_eq!(
            best(&mac(11), &wheels),
            Some("pkg-1.0-cp311-cp311-macosx_11_0_arm64.whl")
        );
        assert_eq!(
            best(&mac(10), &wheels),
            Some("pkg-1.0-cp38-abi3-macosx_11_0_arm64.whl")
        );
        assert_eq!(
            best(&mac(11), &["pkg-1.0-cp311-cp311-win_amd64.whl"]),
            None,
            "a Windows wheel cannot run here"
        );
        assert_eq!(
            best(
                &mac(11),
                &["pkg-1.0-py2-none-any.whl", "pkg-1.0-py3-none-any.whl"]
            ),
            Some("pkg-1.0-py3-none-any.whl")
        );
    }

    #[test]
    fn linux_takes_the_newest_manylinux_the_host_glibc_runs() {
        let wheels = [
            "pkg-1.0-cp312-cp312-manylinux_2_34_x86_64.whl",
            "pkg-1.0-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl",
            "pkg-1.0-cp312-cp312-manylinux_2_28_x86_64.whl",
            "pkg-1.0-cp312-cp312-musllinux_1_2_x86_64.whl",
            "pkg-1.0-cp312-cp312-manylinux_2_28_aarch64.whl",
        ];
        assert_eq!(
            best(&linux(12), &wheels),
            Some("pkg-1.0-cp312-cp312-manylinux_2_28_x86_64.whl")
        );
        assert_eq!(
            best(&linux(12), &["pkg-1.0-cp312-cp312-linux_x86_64.whl"]),
            Some("pkg-1.0-cp312-cp312-linux_x86_64.whl")
        );
    }
}
