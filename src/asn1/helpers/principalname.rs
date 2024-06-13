use crate::asn1::structures::*;
use rasn::prelude::*;

impl PrincipalName {
    pub fn new(name_type: Int32, name_string: SequenceOf<KerberosString>) -> PrincipalName {
        PrincipalName {
            name_type,
            name_string
        }
    }
}
