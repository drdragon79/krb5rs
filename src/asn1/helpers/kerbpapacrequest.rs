use crate::asn1::structures::*;

impl KerbPaPacRequest {
    pub fn new(include_pac: bool) -> KerbPaPacRequest {
        KerbPaPacRequest {
            include_pac
        }
    }
}
