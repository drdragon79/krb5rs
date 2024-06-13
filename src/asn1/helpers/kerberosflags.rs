use crate::asn1::structures::*;
use bitvec::prelude::*;

pub trait KerberosFlagTrait {
    fn with(flags: &[usize]) -> Self;
    fn empty() -> Self;
    fn add(&mut self, flag: usize);
}

impl KerberosFlagTrait for KerberosFlags {
    fn with(flags: &[usize]) -> Self {
        let mut bv = bitvec![u8, Msb0; 0; 32];
        for i in flags {
            bv.set(*i, true)
        }
        bv
    }

    fn empty() -> Self {
        let bv = bitvec![u8, Msb0; 0; 32];
        bv
    }

    fn add(&mut self, flag: usize) {
         self.set(flag, true);
    }

}
