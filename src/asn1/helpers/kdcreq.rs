use crate::asn1::structures::*;
use rasn::prelude::*;

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
