use krb5asn1::{
    constants::{
        pa::*,
        encryption::*,
        kdcoptions::*,
        name::*
    },
    structures::*,
    helpers::*
};
use chrono::prelude::*;
use rand::prelude::*;


pub fn asreq(username: KerberosString, realm: Realm, password: Option<KerberosString>) -> AsReq {
    let mut padata = vec![
        PaData::new(
            PA_PAC_REQUEST,
            KerbPaPacRequest::new(true)
                .derencoder()
                .unwrap()
                .into()
        )
    ];
    if let Some(pass) = password {
        let enc_timestamp = PaData::new(
            PA_ENC_TIMESTAMP,
            todo!("do build pa enc timestamp")
        );
        padata.push(enc_timestamp);
    };
    AsReq::new(
        Some(padata),
        KdcReqBody::new(
            KdcOptions::construct(
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
            Utc::now().into(),
            Some(
                Utc::now().into()
            ),
            thread_rng().gen_range(0..u16::MAX).into(),
            vec![
                aes256_cts_hmac_sha1_96 as i32,
                aes128_cts_hmac_sha1_96 as i32
            ],
            None,
            None,
            None
        )
    )
}
