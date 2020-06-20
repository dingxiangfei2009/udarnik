use std::{
    ffi::{CStr, CString},
    os::raw::{c_char, c_int, c_short, c_uchar, c_uint, c_ulong, c_ushort, c_void},
    os::unix::io::RawFd,
    thread,
};

use backtrace::Backtrace as Bt;
use futures::{
    channel::mpsc::{channel, Receiver, Sender},
    executor::block_on,
    prelude::*,
};
use log::error;
use mio::{unix::EventedFd, Events, Poll, PollOpt, Ready, Token};
use nix::{
    errno::{Errno, EWOULDBLOCK},
    fcntl::{open, OFlag},
    libc::{IFF_TUN, IFF_UP, IFNAMSIZ},
    sys::{
        socket::{sockaddr, socket, AddressFamily, SockFlag, SockType},
        stat,
    },
    unistd,
    unistd::close,
    Error as NixError,
};
use thiserror::Error;

const IFF_NO_PI: c_short = 0x1000;
const IFF_MULTI_QUEUE: c_short = 0x0100;

type Ifname = [c_char; IFNAMSIZ];

#[repr(C)]
#[derive(Clone, Copy)]
union IfRN {
    ifrn_name: Ifname,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Ifmap {
    mem_start: c_ulong,
    mem_end: c_ulong,
    base_addr: c_ushort,
    irq: c_uchar,
    dma: c_uchar,
    port: c_uchar,
}

#[repr(C)]
#[derive(Clone, Copy)]
union IfSU {
    raw_hdlc_proto: *mut c_void,
    cisco: *mut c_void,
    fr: *mut c_void,
    fr_pvc: *mut c_void,
    fr_pvc_info: *mut c_void,
    sync: *mut c_void,
    te1: *mut c_void,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct IfSettings {
    r#type: c_uint,
    size: c_uint,
    ifs_ifsu: IfSU,
}

#[repr(C)]
#[derive(Clone, Copy)]
union IfRU {
    ifru_addr: sockaddr,
    ifru_dstaddr: sockaddr,
    ifru_broadaddr: sockaddr,
    ifru_netmask: sockaddr,
    ifru_hwaddr: sockaddr,
    ifru_flags: c_short,
    ifru_ifindex: c_int,
    ifru_mtu: c_int,
    ifru_map: Ifmap,
    ifru_slave: [c_char; IFNAMSIZ],
    ifru_newname: [c_char; IFNAMSIZ],
    ifru_data: *mut c_char,
    ifru_settings: IfSettings,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IfReq {
    ifr_ifrn: IfRN,
    ifr_ifru: IfRU,
}

mod ioctl {
    use super::*;
    nix::ioctl_write_int!(tun_set_iff, b'T', 202);
    nix::ioctl_write_ptr_bad!(sio_set_if_mtu, nix::libc::SIOCSIFMTU, IfReq);
    nix::ioctl_write_ptr_bad!(sio_set_ifflags, nix::libc::SIOCSIFFLAGS, IfReq);
    nix::ioctl_read_bad!(sio_get_ifflags, nix::libc::SIOCGIFFLAGS, IfReq);
}

struct Fd(RawFd);

impl Drop for Fd {
    fn drop(&mut self) {
        let _ = close(self.0);
    }
}

fn connect_utun_driver() -> Result<Fd, nix::Error> {
    open(
        "/dev/net/tun",
        OFlag::O_RDWR | OFlag::O_NONBLOCK,
        stat::Mode::empty(),
    )
    .map(|fd| Fd(fd))
}

pub struct UtunDev {
    name: CString,
    fd: Fd,
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("invalid name")]
    Name,
    #[error("os: {0}, backtrace: {1:?}")]
    Os(nix::Error, Bt),
}

fn name_to_ifrn_name(name: &str) -> Result<IfRN, Error> {
    let mut ifrn_name = [0; IFNAMSIZ];
    let name: Vec<_> = name.as_bytes().iter().map(|c| *c as c_char).collect();
    let len = name.len();
    if len > IFNAMSIZ {
        return Err(Error::Name);
    }
    ifrn_name[..len].copy_from_slice(&name);
    Ok(IfRN { ifrn_name })
}

fn cstr_name_to_ifrn_name(name: &CStr) -> Result<IfRN, Error> {
    let mut ifrn_name = [0; IFNAMSIZ];
    let name: Vec<_> = name.to_bytes().iter().map(|c| *c as c_char).collect();
    let len = name.len();
    if len > IFNAMSIZ {
        return Err(Error::Name);
    }
    ifrn_name[..len].copy_from_slice(&name);
    Ok(IfRN { ifrn_name })
}

fn ifrn_name_to_name(name: &IfRN) -> CString {
    unsafe {
        match name {
            IfRN { ifrn_name } => {
                let mut name: Vec<_> = ifrn_name.iter().map(|c| *c as i8).collect();
                name.push(0);
                CString::from(CStr::from_ptr(name[..].as_ptr() as *const c_char))
            }
        }
    }
}

impl UtunDev {
    pub fn new(name: &str) -> Result<(Self, Sender<Vec<u8>>, Receiver<Vec<u8>>), Error> {
        let driver = connect_utun_driver().map_err(|e| Error::Os(e, <_>::default()))?;
        let ifr_ifrn = name_to_ifrn_name(&name)?;
        let mut req = IfReq {
            ifr_ifrn,
            ifr_ifru: IfRU {
                ifru_flags: IFF_TUN as c_short | IFF_NO_PI | IFF_MULTI_QUEUE,
            },
        };
        let errno = unsafe {
            ioctl::tun_set_iff(driver.0, &mut req as *mut _ as *const c_void as _)
                .map_err(|e| Error::Os(e, <_>::default()))
        }?;
        if errno != 0 {
            return Err(Error::Os(Errno::from_i32(errno).into(), <_>::default()));
        }
        let name = ifrn_name_to_name(&req.ifr_ifrn);
        let dev = Self::init(name, driver)?;
        let s = Fd(socket(
            AddressFamily::Inet,
            SockType::Datagram,
            SockFlag::empty(),
            None,
        )
        .map_err(|e| Error::Os(e, <_>::default()))?);
        unsafe {
            let errno = ioctl::sio_get_ifflags(s.0, &mut req as *mut _)
                .map_err(|e| Error::Os(e, <_>::default()))?;
            if errno != 0 {
                return Err(Error::Os(Errno::from_i32(errno).into(), <_>::default()));
            }
            req.ifr_ifru.ifru_flags |= IFF_UP as c_short;
            let errno = ioctl::sio_set_ifflags(s.0, &req as *const _)
                .map_err(|e| Error::Os(e, <_>::default()))?;
            if errno != 0 {
                return Err(Error::Os(Errno::from_i32(errno).into(), <_>::default()));
            }
        }
        Ok(dev)
    }

    fn init(name: CString, fd: Fd) -> Result<(Self, Sender<Vec<u8>>, Receiver<Vec<u8>>), Error> {
        let (tx, mut rx) = channel::<Vec<u8>>(4096);
        let tun_fd = fd.0;
        thread::spawn(move || {
            let fd = EventedFd(&tun_fd);
            let poll = match Poll::new() {
                Err(e) => {
                    error!("tun: {}, backtrace: {:?}", e, Bt::new());
                    return;
                }
                Ok(poll) => poll,
            };
            if let Err(e) = poll.register(&fd, Token(0), Ready::writable(), PollOpt::edge()) {
                error!("tun: {}, backtrace: {:?}", e, Bt::new());
                return;
            }
            let mut events = Events::with_capacity(1);
            while let Some(packet) = block_on(rx.next()) {
                loop {
                    match unistd::write(tun_fd, &packet) {
                        Ok(_) => break,
                        Err(NixError::Sys(EWOULDBLOCK)) => {}
                        Err(e) => {
                            error!("tun: {}, backtrace: {:?}", e, Bt::new());
                            return;
                        }
                    }
                    match poll.poll(&mut events, None) {
                        Ok(_) => {}
                        Err(e) => {
                            error!("tun: {}, backtrace: {:?}", e, Bt::new());
                            return;
                        }
                    }
                }
            }
        });
        let (tx_, rx) = channel::<Vec<u8>>(4096);
        let mut this = Self { name, fd };
        this.set_mtu(1500)?;
        thread::spawn(move || {
            let mut tx = tx_;
            let fd = EventedFd(&tun_fd);
            let poll = match Poll::new() {
                Err(e) => {
                    error!("tun: {}, backtrace: {:?}", e, Bt::new());
                    return;
                }
                Ok(poll) => poll,
            };
            if let Err(e) = poll.register(&fd, Token(0), Ready::readable(), PollOpt::edge()) {
                error!("tun: {}, backtrace: {:?}", e, Bt::new());
                return;
            }
            let mut events = Events::with_capacity(1);
            let mut read_buf = [0; 2048];
            loop {
                match unistd::read(tun_fd, &mut read_buf) {
                    Ok(nread) if nread > 0 => {
                        let buf = read_buf[..nread].to_vec();
                        eprintln!("{:x?}", buf);
                        if let Err(e) = tx.try_send(buf) {
                            error!("tun: {}, backtrace: {:?}", e, Bt::new());
                            return;
                        }
                    }
                    Ok(_) => {}
                    Err(NixError::Sys(EWOULDBLOCK)) => {}
                    Err(e) => {
                        error!("tun: {}, backtrace: {:?}", e, Bt::new());
                        return;
                    }
                }
                match poll.poll(&mut events, None) {
                    Ok(_) => {}
                    Err(e) => {
                        error!("tun: {}, backtrace: {:?}", e, Bt::new());
                        return;
                    }
                }
            }
        });
        Ok((this, tx, rx))
    }

    pub fn name(&self) -> &CStr {
        &self.name
    }

    fn set_mtu(&mut self, mtu: usize) -> Result<(), Error> {
        let req = IfReq {
            ifr_ifrn: cstr_name_to_ifrn_name(&self.name)?,
            ifr_ifru: IfRU { ifru_mtu: mtu as _ },
        };
        let s = Fd(socket(
            AddressFamily::Inet,
            SockType::Datagram,
            SockFlag::empty(),
            None,
        )
        .map_err(|e| Error::Os(e, <_>::default()))?);
        let errno =
            unsafe { ioctl::sio_set_if_mtu(s.0, &req).map_err(|e| Error::Os(e, <_>::default())) }?;
        if errno != 0 {
            Err(Error::Os(Errno::from_i32(errno).into(), <_>::default()))
        } else {
            Ok(())
        }
    }

    pub fn fd(&self) -> RawFd {
        self.fd.0
    }
}
