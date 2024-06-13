use crate::asn1::structures::KrbError;

pub enum RespError {
    Decode(rasn::error::DecodeError),
    IO(std::io::Error),
    Krb(KrbError)
}
