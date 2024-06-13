use crate::asn1::structures::*;
use crate::asn1::constants::*;
use rasn::prelude::*;
use crate::crypto::Cipher;

use super::Dercoder;

impl PaData {
    pub fn new(padata_type: Int32, padata_value: OctetString) -> PaData {
        PaData {
            padata_type,
            padata_value
        }
    }
    pub fn build_enc_timestamp(etype: i32, key: &[u8]) -> PaData {
        let paenctsenc = PaEncTsEnc::new();
        let cipher = Cipher::from_etype(etype as usize)
            .unwrap();
        let pt = paenctsenc.dercode()
            .unwrap();
        let ct = cipher.encrypt(key, 1, &pt);
        let encryptedata = EncryptedData::new(etype, None, ct.into());
        PaData::new(
            pa::PA_ENC_TIMESTAMP,
            encryptedata
                .dercode()
                .unwrap()
                .into()
        )
    }
}
