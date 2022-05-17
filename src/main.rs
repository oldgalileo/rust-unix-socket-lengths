#![crate_name = "rust_unix_socket_lengths"]
#![doc(html_playground_url = "https://play.rust-lang.org/")]
//! Navigating the path limits of UNIX domain sockets
//!
//! This was sparked by Leonard Poettering's tweet[^tweet] about a cool workaround for AF_UNIX
//! socket path lengths. Though they vary from system to system, the largest in the wild seems
//! to be 108 chars [^linux], with BSD-derivatives using 104 chars, and more obscure systems
//! running even smaller[^other sizes]. This can turn out to be a real issue[^problems] that can
//! come up when working with XDG paths (e.g. `$XDG_RUNTIME_PATH` as mentioned by Leonard) or when
//! dealing with hashes in paths.
//!
//! They lay out the two ways to resolve issues around this:
//! - Leverage procfs as an alternative location for a file descriptor
//! - Use temp files and rename _after_ the path has been used (checked is too gracious a term,
//! given it's simply a hard-limit)
//!
//! # Step-by-step
//!
//! We start of here with a long path, which we can see in the output exceeds the maximum path
//! length:
//!
//! ```
//! # use std::path::PathBuf;
//! # use std::io::Result;
//! # use std::mem;
//! fn main() -> Result<()> {
//!     let sock_dir = "/tmp/application/lorem/ipsum/dolor/sit/amet/consectetur/adipiscing/elit/sed/do/eiusmod/tempor/incididunt";
//!     std::fs::create_dir_all(&sock_dir)?;
//!
//!     let mut sock_path = PathBuf::from(&sock_dir);
//!     sock_path.push("server.sock");
//!     println!("path: {}\nlength: {}\nmaximum length:{}",
//!         sock_path.to_str().unwrap(),
//!         sock_path.as_os_str().len(),
//!         sockaddr_un_path_max());
//!     Ok(())
//! }
//!
//! # fn sockaddr_un_path_max() -> usize {
//! #     let m = mem::MaybeUninit::<libc::sockaddr_un>::uninit();
//! #     let p =
//! #         unsafe { core::ptr::addr_of!((*(&m as *const _ as *const libc::sockaddr_un)).sun_path) };
//! #
//! #     const fn size_of_raw<T>(_: *const T) -> usize {
//! #         mem::size_of::<T>()
//! #     }
//! #     size_of_raw(p)
//! # }
//! ```
//!
//! **Output**:
//! ```text
//! path: /tmp/application/lorem/ipsum/dolor/sit/amet/consectetur/adipiscing/elit/sed/do/eiusmod/tempor/incididunt/server.sock
//! length: 116
//! maximum length:108
//! ```
//!
//! The methods to avoid running into the `sockaddr_un` path length limit differ between binding
//! and connecting to a socket.
//!
//! ## Binding a socket
//!
//! To **bind** to a long path, we need to setup a symlinked directory to the parent directory of the
//! socket at the end of the long path.
//!
//! Setup the [socket(2)](https://man7.org/linux/man-pages/man2/socket.2.html), then create the
//! path that will serve as the address for the socket to be bound, to within the short directory.
//!
//! [bind(2)](https://man7.org/linux/man-pages/man2/bind.2.html) will create the socket file at the
//! path specified in our sockaddr_un[^linux]'s sun_path. Once we have this, we can rename the file
//! to our obscenely long directory:
//!
//! > `/tmp/short-directory/application.sock -> /var/run/obscenely/.../long/application.sock`
//!
//! ```
//! # use std::path::{PathBuf, Path};
//! # use std::fs::rename;
//! # use std::io::Result;
//! # use std::mem;
//! # use std::os::unix::{fs::symlink, prelude::OsStrExt};
//! # static LONG_PATH: &str = "/tmp/application/lorem/ipsum/dolor/sit/amet/consectetur/adipiscing/elit/sed/do/eiusmod/tempor/incididunt";
//! fn main() -> Result<()> {
//!     let sock_dir = LONG_PATH;
//!     std::fs::create_dir_all(&sock_dir)?;
//!
//!     let mut sock_path = PathBuf::from(&sock_dir);
//!     sock_path.push("server.sock");
//!
//!     let random_dir = "/tmp/tempdir-1652813977685043874";
//!     symlink(&sock_dir, &random_dir)?;
//!
//!     let sock_fd = socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
//!
//!     let sock_temp_path = format!("{}/{}", random_dir, "server.sock");
//!     let (address, address_len) = sockaddr_un_from_path(&sock_temp_path);
//!
//!     bind_and_listen(sock_fd, address, address_len);
//!     rename(&sock_temp_path, sock_path)?;
//! #     unsafe { libc::close(sock_fd); }
//!     Ok(())
//! }
//! #
//! # fn socket(af: libc::c_int, kind: libc::c_int, protocol: libc::c_int) -> i32 {
//! #     unsafe {
//! #         let fd = libc::socket(af, kind, protocol);
//! #         if fd == -1 {
//! #             panic!("socket: {}", std::io::Error::last_os_error());
//! #         }
//! #         fd
//! #     }
//! # }
//! #
//! # fn bind_and_listen(socket: libc::c_int, address: libc::sockaddr_un, address_len: libc::socklen_t) {
//! #     unsafe {
//! #         let ret = libc::bind(socket, &address as *const _ as *const _, address_len);
//! #         if ret == -1 {
//! #             libc::close(socket);
//! #             panic!("failed to bind socket: {}", std::io::Error::last_os_error());
//! #         }
//! #         let ret = libc::listen(socket, 1);
//! #         if ret == -1 {
//! #             libc::close(socket);
//! #             panic!(
//! #                 "failed to listen on socket: {}",
//! #                 std::io::Error::last_os_error()
//! #             );
//! #         }
//! #     }
//! # }
//! #
//! # fn sockaddr_un_from_path<P: AsRef<Path>>(path: P) -> (libc::sockaddr_un, libc::socklen_t) {
//! #     unsafe {
//! #         let mut raw_sockaddr_un: libc::sockaddr_un = mem::zeroed();
//! #         raw_sockaddr_un.sun_family = libc::AF_UNIX as libc::sa_family_t;
//! #         let bytes = path.as_ref().as_os_str().as_bytes();
//! #         if bytes.len() >= raw_sockaddr_un.sun_path.len() {
//! #             panic!("path converted to bytes exceeds sun_path length");
//! #         }
//! #         for (dst, src) in raw_sockaddr_un.sun_path.iter_mut().zip(bytes.iter()) {
//! #             *dst = *src as libc::c_char;
//! #         }
//! #     
//! #         let mut len = sockaddr_un_path_offset() + bytes.len();
//! #         match bytes.get(0) {
//! #             Some(&0) | None => {}
//! #             Some(_) => len += 1,
//! #         }
//! #         (raw_sockaddr_un, len as libc::socklen_t)
//! #     }
//! # }
//! #
//! # fn sockaddr_un_path_offset() -> usize {
//! #     let m = mem::MaybeUninit::<libc::sockaddr_un>::uninit();
//! #     let base = m.as_ptr();
//! #     let sun_path =
//! #         unsafe { core::ptr::addr_of!((*(&m as *const _ as *const libc::sockaddr_un)).sun_path) };
//!
//! #     sun_path as usize - base as usize
//! # }
//! ```
//!
//! ## Connecting a socket
//!
//! To **connect** to a long path, we setup our [socket(2)](https://man7.org/linux/man-pages/man2/socket.2.html)
//! and then open the long path to the socket server socket using the O_PATH option. It's worth
//! noting that Rust [does not allow for opening files with an all-false or empty access mode](https://rust-lang.github.io/rfcs/1252-open-options.html#no-access-mode-set)
//!
//! ```no_run,ignore
//! use std::fs::file;
//!
//! // This will error with io::ErrorKind::InvalidInput
//! let long_socket = File::options()
//!     .custom_flags(libc::O_PATH)
//!     .open(&long_socket_path)?;
//!
//! // This works
//! let long_socket = File::options()
//!     .read(true)
//!     .custom_flags(libc::O_PATH)
//!     .open(&long_socket_path)?;
//! ```
//!
//! > _This is only unintuitive because `O_PATH` is the only exception to the rule that a file most be
//! opened with some access mode. You can call `libc::open(cstr, libc::O_PATH)` directory on UNIX
//! systems without issues. Under normal circumstances, this rule is sensible and hides a potential
//! foot-gun._
//!
//! We can use the fd from the `open(..., O_RDONLY | O_PATH)` to build the path to the
//! procfs fd:
//!
//! > `/proc/self/fd/<fd>`
//!
//! We assume that this path will be shorter than 108/SUN_PATH chars, which allows us to use it as
//! the `sockaddr_un.`'s `sun_path` field. With that, we're able to construct a valid `sockaddr_un`
//! and [connect(2)](https://man7.org/linux/man-pages/man2/connect.2.html) without any trouble.
//!
//! **Demo**:
//! ```no_run
//! # use std::path::{PathBuf, Path};
//! # use std::fs::{rename, File};
//! # use std::io::Result;
//! # use std::mem;
//! # use std::os::unix::{fs::symlink, prelude::{AsRawFd, OpenOptionsExt, OsStrExt}};
//! # static LONG_PATH: &str = "/tmp/application/lorem/ipsum/dolor/sit/amet/consectetur/adipiscing/elit/sed/do/eiusmod/tempor/incididunt";
//! fn main() -> Result<()> {
//!     let sock_dir = LONG_PATH;
//!     std::fs::create_dir_all(&sock_dir)?;
//!
//!     let mut sock_path = PathBuf::from(&sock_dir);
//!     sock_path.push("server.sock");
//!
//!     let sock_fd = socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
//!     // This will fail unless the socket has been bound already. Run `cargo test` with the
//!     // checked out version of this project to see that it works.
//!     let dest_sock_fd = File::options()
//!         .read(true)
//!         .custom_flags(libc::O_PATH)
//!         .open(&sock_path)?;
//!     let dest_sock_fd = dest_sock_fd.as_raw_fd();
//!
//!     let procfs_sock_path = PathBuf::from(format!("/proc/self/fd/{dest_sock_fd}"));
//!     let (address, address_len) = sockaddr_un_from_path(&procfs_sock_path);
//!
//!     connect(sock_fd, address, address_len);
//! #     unsafe { libc::close(sock_fd); }
//!     Ok(())
//! }
//! #
//! # fn socket(af: libc::c_int, kind: libc::c_int, protocol: libc::c_int) -> i32 {
//! #     unsafe {
//! #         let fd = libc::socket(af, kind, protocol);
//! #         if fd == -1 {
//! #             panic!("socket: {}", std::io::Error::last_os_error());
//! #         }
//! #         fd
//! #     }
//! # }
//! #
//! # fn connect(socket: libc::c_int, address: libc::sockaddr_un, address_len: libc::socklen_t) {
//! #     unsafe {
//! #         let ret = libc::connect(socket, &address as *const _ as *const _, address_len);
//! #         if ret == -1 {
//! #             libc::close(socket);
//! #             panic!("failed to connect to socket: {}", std::io::Error::last_os_error());
//! #         }
//! #     }
//! # }
//! #
//! # fn sockaddr_un_from_path<P: AsRef<Path>>(path: P) -> (libc::sockaddr_un, libc::socklen_t) {
//! #     unsafe {
//! #         let mut raw_sockaddr_un: libc::sockaddr_un = mem::zeroed();
//! #         raw_sockaddr_un.sun_family = libc::AF_UNIX as libc::sa_family_t;
//! #         let bytes = path.as_ref().as_os_str().as_bytes();
//! #         if bytes.len() >= raw_sockaddr_un.sun_path.len() {
//! #             panic!("path converted to bytes exceeds sun_path length");
//! #         }
//! #         for (dst, src) in raw_sockaddr_un.sun_path.iter_mut().zip(bytes.iter()) {
//! #             *dst = *src as libc::c_char;
//! #         }
//! #     
//! #         let mut len = sockaddr_un_path_offset() + bytes.len();
//! #         match bytes.get(0) {
//! #             Some(&0) | None => {}
//! #             Some(_) => len += 1,
//! #         }
//! #         (raw_sockaddr_un, len as libc::socklen_t)
//! #     }
//! # }
//! #
//! # fn sockaddr_un_path_offset() -> usize {
//! #     let m = mem::MaybeUninit::<libc::sockaddr_un>::uninit();
//! #     let base = m.as_ptr();
//! #     let sun_path =
//! #         unsafe { core::ptr::addr_of!((*(&m as *const _ as *const libc::sockaddr_un)).sun_path) };
//!
//! #     sun_path as usize - base as usize
//! # }
//! ```
//!
//! [^tweet]: <https://twitter.com/pid_eins/status/1524666972880916480>  
//!
//! [^linux]: Struct definition in the Linux kernel: <https://elixir.bootlin.com/linux/v5.17.8/source/include/uapi/linux/un.h#L9>  
//!
//! [^other sizes]: StackOverflow post discussing these sizes with great references: <https://unix.stackexchange.com/questions/367008/why-is-socket-path-length-limited-to-a-hundred-chars>  
//!
//! [^problems]: Podman ran into this and resolved the connect(2) issue: <https://github.com/containers/podman/issues/8798>
use std::{
    mem,
    os::unix::{
        self,
        prelude::{AsRawFd, OpenOptionsExt, OsStrExt},
    },
    path::{Path, PathBuf},
    thread,
    time::Duration,
};

fn main() {
    let base_name = generate_base_name();
    let too_long_path = prepare_too_long_path(&base_name);
    println!(
        "path: {}\nlength: {}\nmaximum length:{}",
        too_long_path.to_str().unwrap(),
        too_long_path.as_os_str().len(),
        sockaddr_un_path_max()
    );
    std::fs::create_dir_all(&too_long_path).expect("failed to recursively make very long path");
    let mut sock_path = too_long_path.clone();
    sock_path.push("application.sock");

    // Before we can do the simpler connect(2) (useful in 99% of the cases where you'd encounter
    // this due to software over which you have no control binding ridiculous paths), we have
    // to setup our own very-long-path bind

    // First we bind...
    let bind_fd = bind_to_long_path(&sock_path);

    // Then we sleep because I was too lazy to implement a proper RNG and so we could hit filename
    // collisions if we do this too fast...
    thread::sleep(Duration::from_millis(50));

    // Then we connect!
    let (connect_fd, connect_file_fd) = connect_to_long_path(&sock_path);

    unsafe {
        libc::close(connect_fd);
        libc::close(connect_file_fd);
        libc::close(bind_fd);
    }
}

/// Bind an AF_UNIX stream socket to path which exceeds system sockaddr_un path limit
fn bind_to_long_path<P: AsRef<Path>>(dest_sock_path: P) -> i32 {
    let dest_sock_dir = dest_sock_path.as_ref().parent().unwrap();
    let symlink_base_name = generate_base_name();
    let symlink_base_path = std::path::PathBuf::from(format!("/tmp/{symlink_base_name}"));
    unix::fs::symlink(dest_sock_dir, &symlink_base_path)
        .expect("symlink from long socket parent directory to /tmp/ path failed");

    let sock_fd = unsafe {
        let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
        if fd == -1 {
            panic!(
                "failed to start unix domain stream socket: {}",
                std::io::Error::last_os_error()
            );
        }
        fd
    };

    let temp_sock_name = generate_base_name();
    let mut temp_sock_path = symlink_base_path.clone();
    temp_sock_path.push(temp_sock_name);
    let (sock_addr, sock_addr_len) = unsafe { sockaddr_un_from_path(&temp_sock_path) };
    unsafe {
        let ret = libc::bind(sock_fd, &sock_addr as *const _ as *const _, sock_addr_len);
        if ret == -1 {
            libc::close(sock_fd);
            panic!("failed to bind socket: {}", std::io::Error::last_os_error());
        }
        let ret = libc::listen(sock_fd, 1);
        if ret == -1 {
            libc::close(sock_fd);
            panic!(
                "failed to listen on socket: {}",
                std::io::Error::last_os_error()
            );
        }
    }
    std::fs::rename(temp_sock_path, dest_sock_path.as_ref())
        .expect("rename to final destination failed");

    sock_fd
}

/// Connect to an AF_UNIX stream socket which is bound at a path longer than the system sockaddr_un
/// path limit
fn connect_to_long_path<P: AsRef<Path>>(dest_sock_path: P) -> (i32, i32) {
    let sock_fd = unsafe {
        let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
        if fd == -1 {
            panic!(
                "failed to start unix domain stream socket: {}",
                std::io::Error::last_os_error()
            );
        }
        fd
    };

    let dest_sock_fd = std::fs::File::options()
        .read(true)
        .custom_flags(libc::O_PATH)
        .open(&dest_sock_path)
        .expect("failed to open long sock path");

    let dest_sock_fd = dest_sock_fd.as_raw_fd();

    let procfs_sock_path = std::path::PathBuf::from(format!("/proc/self/fd/{dest_sock_fd}"));
    println!("found procfs path: {:?}", procfs_sock_path.to_str());
    let (addr, len) = unsafe { sockaddr_un_from_path(procfs_sock_path) };

    unsafe {
        let ret = libc::connect(sock_fd, &addr as *const _ as *const _, len);
        if ret == -1 {
            libc::close(sock_fd);
            libc::close(dest_sock_fd);
            panic!(
                "failed to connect to socket: {}",
                std::io::Error::last_os_error()
            );
        }
    }
    println!("successfully connected to procfs socket fd!");
    (sock_fd, dest_sock_fd)
}

/// Generates a base-name in the format of `sockets-<UNIX nanosecond timestamp>`
fn generate_base_name() -> String {
    let time_str = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("fun: hop in the delorean, we're going back to the future (boring: time went backwards)")
        .as_nanos()
        .to_string();

    format!("sockets-{time_str}")
}

/// Creates a path that is longer than the system's configured `sockaddr_un->sun_path` length,
/// using "lorem ipsum".
fn prepare_too_long_path(base: &str) -> PathBuf {
    let mut base_path = std::path::PathBuf::from(format!("/tmp/{base}"));
    let mut words_list = vec![
        "lorem",
        "ipsum",
        "dolor",
        "sit",
        "amet",
        "consectetur",
        "adipiscing",
        "elit",
        "sed",
        "do",
        "eiusmod",
        "tempor",
        "incididunt",
    ];
    words_list.reverse();
    let max_sockaddr_un_path_len = sockaddr_un_path_max().try_into().unwrap();
    while base_path.as_os_str().len() < max_sockaddr_un_path_len {
        if let Some(word) = words_list.pop() {
            base_path.push(word);
        } else {
            panic!("word list not big enough to be problematic for linux");
        }
    }
    base_path
}

/// Programmatically get the size of the sun_path sockaddr_un field which varies from 92 to 108
/// bytes.
///
/// Admittedly it would likely be fair game to just say "hey, this will only ever work on
/// normal systems, and since 108 is the biggest of all standard systems AND because we're using
/// UNIX domain sockets which won't work on BSD-derived systems anyway, we should just hardcode
/// this". But uhh, why are you hear if not for weird architecture details?
///
/// This is a much niftier trick than using `raw_ref_op`. Thanks @Alyssa Haroldsen!
/// Credit: <https://stackoverflow.com/a/70222282/1733135>
fn sockaddr_un_path_max() -> usize {
    let m = mem::MaybeUninit::<libc::sockaddr_un>::uninit();
    // According to https://doc.rust-lang.org/stable/std/ptr/macro.addr_of_mut.html#examples,
    // you can dereference an uninitialized MaybeUninit pointer in addr_of!
    // Raw pointer deref in const contexts is stabilized in 1.58:
    // https://github.com/rust-lang/rust/pull/89551
    let p =
        unsafe { core::ptr::addr_of!((*(&m as *const _ as *const libc::sockaddr_un)).sun_path) };

    const fn size_of_raw<T>(_: *const T) -> usize {
        mem::size_of::<T>()
    }
    size_of_raw(p)
}

fn sockaddr_un_path_offset() -> usize {
    let m = mem::MaybeUninit::<libc::sockaddr_un>::uninit();
    let base = m.as_ptr();
    let sun_path =
        unsafe { core::ptr::addr_of!((*(&m as *const _ as *const libc::sockaddr_un)).sun_path) };

    sun_path as usize - base as usize
}

unsafe fn sockaddr_un_from_path<P: AsRef<Path>>(path: P) -> (libc::sockaddr_un, libc::socklen_t) {
    let mut raw_sockaddr_un: libc::sockaddr_un = mem::zeroed();
    raw_sockaddr_un.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let bytes = path.as_ref().as_os_str().as_bytes();
    if bytes.len() >= raw_sockaddr_un.sun_path.len() {
        panic!("path converted to bytes exceeds sun_path length");
    }
    for (dst, src) in raw_sockaddr_un.sun_path.iter_mut().zip(bytes.iter()) {
        *dst = *src as libc::c_char;
    }

    let mut len = sockaddr_un_path_offset() + bytes.len();
    match bytes.get(0) {
        Some(&0) | None => {}
        Some(_) => len += 1,
    }
    (raw_sockaddr_un, len as libc::socklen_t)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unix::net::UnixListener;

    #[test]
    #[should_panic(expected = "path must be shorter than SUN_LEN")]
    fn example_failure_when_path_too_long() {
        let base_name = generate_base_name();
        let too_long_path = prepare_too_long_path(&base_name);
        std::fs::create_dir_all(&too_long_path).expect("failed to recursively make very long path");
        let mut sock_path = too_long_path.clone();
        sock_path.push("application.sock");
        let _ = match UnixListener::bind(sock_path) {
            Err(err) => panic!("failed to bind socket: {err}"),
            Ok(_) => panic!("should not be possible!!!"),
        };
    }

    #[test]
    fn successfully_bind_to_long_path() {
        let base_name = generate_base_name();
        let too_long_path = prepare_too_long_path(&base_name);
        std::fs::create_dir_all(&too_long_path).expect("failed to recursively make very long path");
        let mut sock_path = too_long_path.clone();
        sock_path.push("application.sock");

        let bind_fd = bind_to_long_path(&sock_path);

        unsafe {
            libc::close(bind_fd);
        }
    }

    #[test]
    fn successfully_bind_and_connect_to_long_path() {
        let base_name = generate_base_name();
        let too_long_path = prepare_too_long_path(&base_name);
        std::fs::create_dir_all(&too_long_path).expect("failed to recursively make very long path");
        let mut sock_path = too_long_path.clone();
        sock_path.push("application.sock");

        let bind_fd = bind_to_long_path(&sock_path);

        thread::sleep(Duration::from_millis(50));

        let (connect_fd, connect_file_fd) = connect_to_long_path(&sock_path);

        unsafe {
            libc::close(connect_fd);
            libc::close(connect_file_fd);
            libc::close(bind_fd);
        }
    }
}
