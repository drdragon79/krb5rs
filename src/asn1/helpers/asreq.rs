use crate::asn1::{
    constants::{
        encryption::*, kdcoptions::*, name::*, pa::*, protocol::*
    }, helpers::*, structures::*
};
use crate::crypto::Key;
use crate::network::Kdc;
use rand::prelude::*;
use crate::errors::RespError;
use chrono::prelude::*;
use super::{Dercoder, Sender};
use std::time::Duration;

impl AsReq {
    /// AS-REQ Constructor
    pub fn new(
        padata: Option<SequenceOf<PaData>>,
        req_body: KdcReqBody
    ) -> AsReq {
        AsReq(
            KdcReq::new(pvno, 10 , padata, req_body)
        )
    }

    /// send and parse response from server.
    pub fn send_and_parse(&self, dc: &Kdc) -> Result<AsRep, RespError> {
        let response = self.send_to(dc);
        if let Err(io_err) = response {
            Err(RespError::IO(io_err))
        } else {
            let response = response.unwrap();
            AsRep::parse(&response)
                .map_err(|_| {
                    match KrbError::parse(&response) {
                        Ok(krberror) => RespError::Krb(krberror),
                        Err(decode_err) => RespError::Decode(decode_err)
                    }
                })
        }
    }

    /// AS-REQ builder with username & password
    pub fn build(username: KerberosString, realm: Realm, key: Option<Key>) -> AsReq {
        let time = Utc::now().with_nanosecond(0).unwrap() + Duration::from_secs(86400);
        let mut padata = vec![
            PaData::new(
                PA_PAC_REQUEST,
                KerbPaPacRequest::new(true)
                    .dercode()
                    .unwrap()
                    .into()
            )
        ];
        if let Some(key) = key {
            let enctimestamppa = PaData::build_enc_timestamp(key.etype, &key.key);
            padata.push(enctimestamppa);
        }
        AsReq::new(
            Some(padata),
            KdcReqBody::new(
                KdcOptions::with(
                    &[
                        forwardable,
                        renewable,
                        proxiable
                    ]
                ),
                Some(
                    PrincipalName::new(
                        KRB_NT_PRINCIPAL,
                        vec![username]
                    )
                ),
                realm.clone(),
                Some(
                    PrincipalName::new(
                        KRB_NT_PRINCIPAL,
                        vec![
                            KerberosString::from_bytes(b"krbtgt").unwrap(),
                            realm
                        ]
                    )
                ),
                None,
                time.into(),
                Some(
                    time.into()
                ),
                thread_rng().gen_range(0..u16::MAX).into(),
                vec![
                    aes256_cts_hmac_sha1_96 as i32,
                    aes128_cts_hmac_sha1_96 as i32,
                    rc4_hmac as i32
                ],
                None,
                None,
                None
            )
        )
    }
}
