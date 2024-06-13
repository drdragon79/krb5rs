use crate::asn1::{
    structures::*,
    constants::*
};

use super::Dercoder;

impl KrbError {
    /// Get String version of the error code
    pub fn geterrorvalue(&self) -> Option<String> {
        krberrors::get_error(self.error_code)
    }

    /// Parse salt from ETYPE_INFO2
    pub fn get_salt(&self) -> Result<EtypeInfo2Entry, rasn::error::DecodeError> {
        let e_data = self.e_data
            .as_ref()
            .unwrap();
        let method_data = MethodData::parse(e_data)?;
        for pa_data in method_data {
            if pa_data.padata_type == pa::PA_ETYPE_INFO2 {
                let entry = EtypeInfo2::parse(&pa_data.padata_value)?;
                return Ok(entry[1].clone());
            }
        }
        panic!("Salt Not Found!");
    }
}
