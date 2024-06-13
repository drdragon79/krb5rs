#![allow(dead_code)]
#![allow(clippy::too_many_arguments)]

use rasn::prelude::*;
use crate::network::Kdc;

mod asreq;
mod kdcreq;
mod kdcreqbody;
mod padata;
mod principalname;
mod kerbpapacrequest;
mod kerberosflags;
pub use kerberosflags::KerberosFlagTrait;
mod krberror;
mod paenctsenc;
mod encrypteddata;

/// Der Encoder and Decoder Trait
pub trait Dercoder {
    fn dercode(&self) -> Result<Vec<u8>, rasn::error::EncodeError>;
    fn parse(encoded: &[u8]) -> Result<Self, rasn::error::DecodeError> where Self: Sized;
}

/// Implement Dercoder for every type that implements Encode & Decode
impl<T: Sized + Decode + Encode> Dercoder for T {
    fn dercode(&self) -> Result<Vec<u8>, rasn::error::EncodeError> {
        let dercoder = rasn::Codec::Der;
        dercoder.encode_to_binary(self)
    }

    fn parse(encoded: &[u8]) -> Result<T, rasn::error::DecodeError> {
        let dercoder = rasn::Codec::Der;
        dercoder.decode_from_binary(encoded)
    }
}

// Sender Trait
pub trait Sender {
    fn send_to(&self, dc: &Kdc) -> std::io::Result<Vec<u8>>;
}

impl<T: Dercoder> Sender for T {
    fn send_to(&self, dc: &Kdc) -> std::io::Result<Vec<u8>>{
       dc.talk_tcp(&self.dercode().unwrap())
    }
}
