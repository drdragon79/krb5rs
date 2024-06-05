#![allow(dead_code)]
#![allow(clippy::too_many_arguments)]

use rasn::prelude::*;
use super::{
    structures::*,
    constants::*
};
use bitvec::prelude::*;

impl AsReq {
    pub fn new(
        padata: Option<SequenceOf<PaData>>,
        req_body: KdcReqBody
    ) -> AsReq {
        AsReq(
            KdcReq::new(protocol::pvno, 10 , padata, req_body)
        )
    }
}

impl KdcReq {
    pub fn new(
        pvno: Int32,
        msg_type: Int32,
        padata: Option<SequenceOf<PaData>>,
        req_body: KdcReqBody
    ) -> KdcReq {
        KdcReq {
            pvno,
            msg_type,
            padata,
            req_body
        }
    }
}

impl KdcReqBody {
    pub fn new(
        kdc_options: KdcOptions,
        cname: Option<PrincipalName>,
        realm: Realm,
        sname: Option<PrincipalName>,
        from: Option<KerberosTime>,
        till: KerberosTime,
        rtime: Option<KerberosTime>,
        nonce: UInt32,
        etype: SequenceOf<Int32>,
        addresses: Option<HostAddresses>,
        enc_authorization_data: Option<EncryptedData>,
        additional_tickets: Option<SequenceOf<Ticket>>
    ) -> KdcReqBody {
        KdcReqBody {
            kdc_options,
            cname,
            realm,
            sname,
            from,
            till,
            rtime,
            nonce,
            etype,
            addresses,
            enc_authorization_data,
            additional_tickets
        }
    }
}

impl PaData {
    pub fn new(padata_type: Int32, padata_value: OctetString) -> PaData {
        PaData {
            padata_type,
            padata_value
        }
    }
}

impl PrincipalName {
    pub fn new(name_type: Int32, name_string: SequenceOf<KerberosString>) -> PrincipalName {
        PrincipalName {
            name_type,
            name_string
        }
    }
}

impl KerbPaPacRequest {
    pub fn new(include_pac: bool) -> KerbPaPacRequest {
        KerbPaPacRequest {
            include_pac
        }
    }
}

pub trait KerberosFlagTrait {
    fn construct(flags: &[usize]) -> Self;
    
}

impl KerberosFlagTrait for KdcOptions {
    fn construct(flags: &[usize]) -> Self {
        let mut bv = bitvec![u8, Msb0; 0; 32];
        for i in flags {
            bv.set(*i, true)
        }
        bv
    }
}

impl KrbError {
    pub fn geterrorvalue(&self) -> Option<String> {
        krberror::get_error(self.error_code)
    }
}

/// Der Encoder and Decoder Trait
pub trait Dercoder {
    fn derencoder(&self) -> Result<Vec<u8>, rasn::error::EncodeError>;
    fn derdecoder(encoded: &[u8]) -> Result<Self, rasn::error::DecodeError> where Self: Sized;
}

/// Implement Dercoder for every type that implements Encode & Decode
impl<T: Sized + Decode + Encode> Dercoder for T {
    fn derencoder(&self) -> Result<Vec<u8>, rasn::error::EncodeError> {
        let dercoder = rasn::Codec::Der;
        dercoder.encode_to_binary(self)
    }

    fn derdecoder(encoded: &[u8]) -> Result<T, rasn::error::DecodeError> {
        let dercoder = rasn::Codec::Der;
        dercoder.decode_from_binary(encoded)
    }
}

