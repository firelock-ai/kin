# Filesystem projection

The graph is the authority. Every commit, every entity, every relation lives in
Kin's graph, and that is what `kin` and the daemon answer from. A projection is
how you see that truth as ordinary files, so your editor, your compiler and your
build system keep working without knowing anything changed.

Kin has four projections. They differ in how the files reach your tools, not in
where the truth comes from.

| Mode | How files reach your tools |
| --- | --- |
| `shim` | `libkin_vfs_shim` is injected into each process by the shell hook, so intercepted libc calls answer from the graph. |
| `nfs` | `kin-vfs` runs an NFSv3 server and the kernel mounts it. |
| `fuse` | `kin-vfs` serves a FUSE filesystem the kernel mounts. |
| `projfs` | Windows projects the repository in place through the Windows Projected File System. |

## What each one needs, per platform

An empty cell means that mode does not exist on that platform at all, which is
different from a mode you could install and have not.

| | macOS | Linux | Windows |
| --- | --- | --- | --- |
| `shim` | ships with Kin | ships with Kin | |
| `nfs` | `mount_nfs`, already in the base system | `nfs-common` (Debian, Ubuntu) or `nfs-utils` (Fedora, Arch) | `Enable-WindowsOptionalFeature -Online -FeatureName ServicesForNFS-ClientOnly`, on Pro, Enterprise and Education only, and it mounts to a drive letter rather than projecting in place |
| `fuse` | FUSE-T or macFUSE | your distribution's `fuse3` package | |
| `projfs` | | | `Enable-WindowsOptionalFeature -Online -FeatureName Client-ProjFS -NoRestart`, on every SKU including Home |

`kin vfs status` prints this per mode for the machine you are on, with the
literal result of each probe. The table lives in one place in the code, so what
the CLI tells you and what this page says cannot drift.

## Which one you get

Kin picks in this order, and takes the first mode that a live probe says can
run here:

- macOS: `nfs`, then `fuse`, then `shim`
- Linux: `fuse`, then `nfs`, then `shim`
- Windows: `projfs`, then `nfs`
- everywhere else: `shim`

A mount beats the shim because a mount cannot be taken away from a process. The
kernel serves the files, so every tool on the machine sees graph truth whether
or not it was started from a shell Kin configured. The shim is injected, and an
operating system is allowed to refuse the injection: a container, a signed
binary, macOS SIP, or a static binary that never calls libc all leave that
process reading raw disk. Nothing crashes when that happens, which is exactly
why it needs to be reported rather than assumed.

One gap is not about refusal at all. The shim interposes libc and nothing else,
so a binary that reaches the kernel without libc goes straight around it. A Go
binary built the usual way is that binary: it issues its own syscalls, and
inside a projected repository it reads the working copy on the same path where
git, Node, Python and the coreutils read graph truth. Nothing can hook a call
that names no symbol, so `kin vfs status` prints the limit under `shim` rather
than leaving you to find it. The `nfs` and `fuse` mounts have no such gap,
because the kernel serves every process on the host. If your toolchain is Go,
prefer a mount.

Node used to be in that class and no longer is, which is worth knowing if you
read the older advice. libuv issues `statx` itself rather than calling a libc
stat entry point, so for a release `node` answered a stat from the working copy
where every libc caller got the fail-closed error. It reaches the kernel through
glibc's `syscall(2)` wrapper rather than through the instruction, though, and a
wrapper is a symbol like any other, so the shim interposes it and Node now reads
the projection here.

Between the two mounts, each platform's native one comes first. macOS carries an
NFS client in the base system while FUSE there needs FUSE-T or macFUSE
installed. Linux carries libfuse far more widely than it carries a configured
NFS client.

On macOS and Linux the shim is last, and it is a real answer rather than a
failure: it is what makes graph-first adoption work on a host that will mount
nothing.

Windows runs a different order for a different reason. There is no shim to fall
back to, because there is no library the shell hook can inject, so ProjFS both
leads and is the floor. The NFS client is second rather than a compatibility
layer: it ships only on Pro, Enterprise and Education, and it mounts to a drive
letter instead of projecting the repository where it already is. That is also
why `kin doctor` on Windows never reports that nothing is missing when no
projection is running. ProjFS is present on every SKU and only needs enabling,
so an unavailable projection there is always something you can fix.

## Turning it on and off

```
kin vfs on                      # engage the chosen projection for this repository
kin vfs on --mode nfs           # ask for a specific one
kin vfs off                     # disengage it
kin vfs status                  # what is in force, probed live
kin vfs status --json           # the same, machine-readable
```

Mounts appear under `~/Kin` by default, which is user-writable without sudo,
survives an unmount, and can be dragged into a file manager's sidebar. Kin reads
the mount point a running server actually published rather than assuming that
default, because a server that chose somewhere else would otherwise be reported
as not mounted.

`kin setup` also picks a mode and records it in `~/.kin/config/setup.toml` under
`[projection] mode`. A mode you asked for is what gets recorded. If it cannot
run, Kin falls back and says so, and the recording is left alone so `kin doctor`
can keep telling you that the mode you chose is not the mode you have.

Turning the shim on is the one case where a command cannot do the whole job.
The shell hook injects the library into each process as it starts, so it cannot
reach into a shell that is already running. Start a new shell, or run
`exec $SHELL -l`, and the repository is projected. Turning the shim off works
the same way: set `KIN_VFS_DISABLE=1` and new shells skip it.

## Knowing whether it worked

Two surfaces answer this, and both run a probe rather than reading a
configuration file back to you.

`kin doctor` carries a `Projection in force` row:

```
mode=shim mounted=n/a readable=yes writable=n/a degraded=no
```

`mounted` is `n/a` for the shim, which is injected rather than mounted, and
`yes` or `no` for a mount, measured by comparing the device id of the mount
point against its parent. `readable` lists the projected directory.

`writable` is asked of a mount, by writing a probe file into the mount point
and reading the bytes back, because a write that is never read back proves
nothing: a mount can accept a write into a cache it never serves. It is `n/a`
for the shim, which serves reads out of the graph and lets writes land on disk
where admission picks them up. Nothing about writing is the shim's to decide,
and probing it anyway would mean creating and deleting a file inside your
repository every time you ran `kin status`.

## What happens to a write

A write through a mount stages into the served repository's working copy, and
every staged path is admitted into graph truth through the same seam
`kin commit` uses, so `kin log` carries it. That is what makes "the graph is the
authority" literally true for a mounted projection rather than an aspiration.
`kin vfs off` admits whatever is staged before it unmounts, so turning the
projection off does not strand work.

Under the shim, writes land on disk and reach the graph through admission. The
old `/vfs/write-notify` and `/vfs/file-changed` routes that used to acknowledge
a write are gone, and the daemon answers 404 for both.

`degraded` is `yes` when the mode running is not the mode you asked for, or when
the mode running failed one of its own probes.

`kin status` and `kin graph status` both print the same line, so you can tell
whether the file you just edited went through the graph without running a second
command.

When a mount is configured but not mounted, the read and write probes are
skipped rather than run. Probing an empty mount point would describe the host
directory underneath it and report a healthy projection that is not there.

## When a mount is not available

Kin's release workflow now builds the shipped `kin-vfs` with `--features nfs` on
macOS and `--features fuse` on Linux, so a stock install carries its platform's
mount. Kin still asks the driver which subcommands it carries rather than
assuming, because an older install predates those flags; where a mount feature
is absent it reports that and falls back to the shim with a message. To build a
driver with the other platform's feature, or to test an unreleased one:

```
cargo build --release -p kin-vfs-cli --features nfs
cargo build --release -p kin-vfs-cli --features fuse
```

Point Kin at the driver you built with `KIN_VFS_BIN`, rather than reordering
PATH:

```
export KIN_VFS_BIN=/path/to/kin-vfs
kin vfs status
```

When `KIN_VFS_BIN` is set it is the only driver Kin considers, so a pin naming
a file that is not there reports an absent driver instead of quietly falling
back to the installed one.

`kin vfs status` prints, per mode, the literal result of its probe and what to
do about an unavailable one.
