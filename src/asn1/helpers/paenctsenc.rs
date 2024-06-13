use crate::asn1::structures::*;
use chrono::prelude::*;

impl PaEncTsEnc {
    pub fn new() -> PaEncTsEnc {
        let time_now = Utc::now();
        let microsecond = time_now.timestamp_subsec_micros();
        let time_now = time_now.with_nanosecond(0).unwrap();
        PaEncTsEnc {
            patimestamp: time_now.into(),
            pausec: Some(microsecond)
        }
    }
}
