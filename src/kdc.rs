use std::net::{
    SocketAddr,
    TcpStream,
    UdpSocket
};
use std::time::Duration;
use std::io::{self, Read, Write};
use log::*;

use crate::helpers;

pub struct KDC {
    ip_addr: SocketAddr,
    realm: Option<String>
}

impl KDC {
    pub fn new(ip_addr: SocketAddr, realm: Option<String>) -> Self {
        let realm = realm.or_else(|| helpers::get_adr_from_realm(ip_addr).ok());
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
        dc_socket.write(&req_length_be)?;
        dc_socket.write(raw_msg)?;

        let mut res_len_be = [11 as u8; 4];
        dc_socket.read_exact(&mut res_len_be)?;
        println!("{:?}", res_len_be);
        let res_len = u32::from_be_bytes(res_len_be);
        println!("{:?}", res_len);
        let mut res = vec![0; res_len as usize];
        dc_socket.read_exact(&mut res)?;
        Ok(res)
    }

    pub fn talk_udp(&self, raw_msg: &[u8]) -> std::io::Result<Vec<u8>> {
        let dc_socket = UdpSocket::bind(("0.0.0.0", 6500))?;
        dc_socket.connect(&self.ip_addr)?;
        
        dc_socket.send(raw_msg)?;
        let mut res_buffer = [0 as u8; u16::MAX as usize];
        let res_len = dc_socket.recv(&mut res_buffer)?;
        Ok(res_buffer[..res_len].to_vec())
    }
}