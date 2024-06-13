use crate::asn1::structures::*;
use rasn::prelude::*;

impl EncryptedData {
    pub fn new(etype: Int32, kvno: Option<UInt32>, cipher: OctetString) -> EncryptedData {
        EncryptedData {
            etype,
            kvno,
            cipher
        }
    }
}

