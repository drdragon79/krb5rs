#![allow(dead_code)]
use std::net::{
    SocketAddr,
    TcpStream,
    UdpSocket
};
use std::time::Duration;
use std::io::{self, Read, Write};
use log::*;

pub struct Kdc {
    ip_addr: SocketAddr,
    pub realm: String
}

impl Kdc {
    pub fn new(ip_addr: SocketAddr, realm: String) -> Self {
        Self {
            ip_addr,
            realm
        }
    }

    pub fn talk(&self, raw_msg: &[u8]) -> io::Result<Vec<u8>> {
        Ok(
            self.talk_tcp(raw_msg)
                .unwrap_or(self.talk_udp(raw_msg)?)
        )
    }
    
    pub fn talk_tcp(&self, raw_msg: &[u8]) -> io::Result<Vec<u8>> {
        let mut dc_socket = TcpStream::connect_timeout(&self.ip_addr, Duration::from_secs(5))?;

        let req_length_be = (raw_msg.len() as u32).to_be_bytes();
        dc_socket.write_all(&req_length_be)?;
        dc_socket.write_all(raw_msg)?;

        let mut res_len_be = [11u8; 4];
        dc_socket.read_exact(&mut res_len_be)?;
        debug!("{:?}", res_len_be);
        let res_len = u32::from_be_bytes(res_len_be);
        debug!("TALK_TCP>res_len: {:?}", res_len);
        let mut res = vec![0; res_len as usize];
        dc_socket.read_exact(&mut res)?;
        Ok(res)
    }

    pub fn talk_udp(&self, raw_msg: &[u8]) -> std::io::Result<Vec<u8>> {
        let dc_socket = UdpSocket::bind(("0.0.0.0", 6500))?;
        dc_socket.connect(self.ip_addr)?;
        
        dc_socket.send(raw_msg)?;
        let mut res_buffer = [0u8; u16::MAX as usize];
        let res_len = dc_socket.recv(&mut res_buffer)?;
        Ok(res_buffer[..res_len].to_vec())
    }
}
