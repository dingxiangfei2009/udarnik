use std::{
    collections::VecDeque,
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
    sys::{socket::sockaddr, stat},
    unistd,
    unistd::close,
    Error as NixError,
};
use thiserror::Error;

const IFHWADDRLEN: usize = 6;
const IFNAMSIZ: usize = 16;
const IFF_TUN: c_short = 0x0001;
const IFF_NO_PI: c_short = 0x1000;
const IFF_MULTI_QUEUE: c_short = 0x0100;
const IFF_ATTACH_QUEUE: c_short = 0x0200;
const IFF_DETACH_QUEUE: c_short = 0x0400;

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
    nix::ioctl_write_int!(tun_set_iff, b'T', 202);
    nix::ioctl_write_int_bad!(sio_set_if_mtu, 0x8922);
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
    let name: Vec<_> = name.as_bytes().iter().map(|c| *c as i8).collect();
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
                ifru_flags: IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE,
            },
        };
        let errno = unsafe {
            ioctl::tun_set_iff(driver.0, &mut req as *mut _ as *mut c_void as _)
                .map_err(|e| Error::Os(e, <_>::default()))
        }?;
        if errno != 0 {
            return Err(Error::Os(Errno::from_i32(errno).into(), <_>::default()));
        }
        let name = ifrn_name_to_name(&req.ifr_ifrn);
        Ok(Self::init(name, driver))
    }

    fn init(name: CString, fd: Fd) -> (Self, Sender<Vec<u8>>, Receiver<Vec<u8>>) {
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
            let mut buf = VecDeque::<u8>::new();
            let mut read_buf = [0; 2048];
            loop {
                if buf.len() > 40960 {
                    error!("tun: unable to decode first packet, buffer overflow");
                    return;
                }
                match unistd::read(tun_fd, &mut read_buf) {
                    Ok(nread) if nread > 0 => {
                        buf.extend(&read_buf[..nread]);
                        match buf[0] & 0xf {
                            6 => {
                                if buf.len() < 6 {
                                    continue;
                                }
                                let packet_len = u16::from_be_bytes([buf[4], buf[5]]) as usize + 40;
                                if buf.len() >= packet_len {
                                    let packet = buf.drain(..packet_len).collect();
                                    if let Err(e) = block_on(tx.send(packet)) {
                                        error!("tun: {}", e);
                                        return;
                                    }
                                }
                                continue;
                            }
                            4 => {
                                if buf.len() < 4 {
                                    continue;
                                }
                                let packet_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
                                if buf.len() >= packet_len {
                                    let packet = buf.drain(..packet_len).collect();
                                    if let Err(e) = block_on(tx.send(packet)) {
                                        error!("tun: {}", e);
                                        return;
                                    }
                                }
                                continue;
                            }
                            _ => {
                                error!("tun: not an IP packet");
                                return;
                            }
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
        (Self { name, fd }, tx, rx)
    }

    pub fn name(&self) -> &CStr {
        &self.name
    }

    pub fn set_mut(&mut self, mtu: usize) -> Result<(), Error> {
        let req = IfReq {
            ifr_ifrn: IfRN {
                ifrn_name: [0; IFNAMSIZ],
            },
            ifr_ifru: IfRU { ifru_mtu: mtu as _ },
        };
        let errno = unsafe {
            ioctl::sio_set_if_mtu(self.fd.0, &req as *const _ as *const c_void as _)
                .map_err(|e| Error::Os(e, <_>::default()))
        }?;
        if errno != 0 {
            Err(Error::Os(Errno::from_i32(errno).into(), <_>::default()))
        } else {
            Ok(())
        }
    }

    pub fn make_clone(&self) -> Result<(Self, Sender<Vec<u8>>, Receiver<Vec<u8>>), Error> {
        let driver = connect_utun_driver().map_err(|e| Error::Os(e, <_>::default()))?;

        let dev_name = self.name.to_bytes();
        let dev_name_len = dev_name.len();
        if dev_name_len > IFNAMSIZ {
            return Err(Error::Name);
        }
        let mut ifrn_name: Ifname = [0; IFNAMSIZ];
        unsafe {
            std::ptr::copy_nonoverlapping(
                dev_name.as_ptr() as *const i8,
                ifrn_name.as_mut_ptr() as *mut _,
                dev_name_len,
            );
        }
        let ifr_ifrn = IfRN { ifrn_name };

        let mut req = IfReq {
            ifr_ifrn,
            ifr_ifru: IfRU {
                ifru_flags: IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE,
            },
        };
        let errno = unsafe {
            ioctl::tun_set_iff(driver.0, &mut req as *mut _ as *mut c_void as _)
                .map_err(|e| Error::Os(e, <_>::default()))
        }?;
        if errno != 0 {
            return Err(Error::Os(Errno::from_i32(errno).into(), <_>::default()));
        }
        let name = ifrn_name_to_name(&req.ifr_ifrn);
        Ok(Self::init(name, driver))
    }
}
