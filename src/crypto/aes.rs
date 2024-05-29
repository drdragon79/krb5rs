use aes::cipher::{BlockEncryptMut, KeyIvInit};
use sha1::Sha1;
use pbkdf2::pbkdf2_hmac;
use log::*;
use crate::crypto::nfold;


pub enum AES {
    AES128,
    AES256
}

impl AES {
    fn keysize(&self) -> usize {
        match self {
            AES::AES128 => 128/8,
            AES::AES256 => 256/8
        }
    }

    fn blocksize(&self) -> usize {
        16
    }

    pub fn tk(&self, password: &[u8], salt: &[u8], rounds: u32) -> Vec<u8> {
        let mut buff =  [0u8; 256];
        pbkdf2_hmac::<Sha1>(password, salt, rounds, &mut buff);
        buff[..self.keysize()].to_vec()
    }

    pub fn dk(&self, constant: &[u8], key: &[u8]) -> Vec<u8> {
        let mut wkconstant = if constant.len() < self.blocksize() {
            nfold(constant, self.blocksize())
        } else {
            constant.to_vec()
        };

        let mut dervivedkey = Vec::new();
        
        while dervivedkey.len() < self.keysize() {
            let key_n = self.encrypt_cts(&wkconstant, key);
            dervivedkey.append(&mut key_n.clone());
            wkconstant = key_n;
        }
        dervivedkey
    }

    pub fn encrypt_cts(&self, plaintext: &[u8], key: &[u8]) -> Vec<u8> {
        let pad = if plaintext.len() % self.blocksize() == 0 {
            0
        } else {
            self.blocksize() - (plaintext.len() % self.blocksize())
        };
        let mut padded_plaintext = plaintext
            .to_vec();
        padded_plaintext.append(&mut vec![0u8; pad]);

        let iv =  vec![0u8; self.blocksize()];

        let plaintext_len = padded_plaintext.len();

        let ciphertext = match self {
            AES::AES128 => {
                type AES128CBC = cbc::Encryptor<aes::Aes128>;
                let encryptor = AES128CBC::new(key.into(), iv[..].into());
                encryptor.encrypt_padded_mut
                    ::<cbc::cipher::block_padding::NoPadding>
                    (&mut padded_plaintext, plaintext_len)

            }
            AES::AES256 => {
                type AES256CBC = cbc::Encryptor<aes::Aes256>;
                let encryptor = AES256CBC::new(key.into(), iv[..].into());
                encryptor.encrypt_padded_mut
                    ::<cbc::cipher::block_padding::NoPadding>
                    (&mut padded_plaintext, plaintext_len)
            }
        }
            .unwrap_or_else(|e| {
                error!("Encryption Error <PadError>: {}", e);
                std::process::exit(0);
            });
        ciphertext.to_vec()
    }

    pub fn decrypt_cts() -> Vec<u8> {
        todo!()
    }

    pub fn string2key(&self,password: &[u8], salt: &[u8], iteration: Option<u32>) -> Vec<u8> {
        let rounds = iteration
            .unwrap_or(4096);
        let tkey = self.tk(password, salt, rounds);
        self.dk(b"kerberos", &tkey)
    }
} 

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tk1() {
        let aes128= AES::AES128;
        let result  = aes128.tk(b"password", b"ATHENA.MIT.EDUraeburn", 1);
        let result = hex::encode(result);
        let expected = "cdedb5281bb2f801565a1122b2563515".to_string();
        assert_eq!(result, expected);
    }
    #[test]
    fn test_tk2() {
        let aes256 = AES::AES256;
        let result  = aes256.tk(b"password", b"ATHENA.MIT.EDUraeburn", 1);
        let result = hex::encode(result);
        let expected = "cdedb5281bb2f801565a1122b25635150ad1f7a04bb9f3a333ecc0e2e1f70837".to_string();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_string2key1() {
        let aes = AES::AES128;
        let aeskey = aes.string2key(b"password", b"ATHENA.MIT.EDUraeburn", Some(1));
        assert_eq!(hex::encode(aeskey), "42263c6e89f4fc28b8df68ee09799f15");
    }
    #[test]
    fn test_string2key2() {
        let aes = AES::AES256;
        let aeskey = aes.string2key(b"password", b"ATHENA.MIT.EDUraeburn", Some(1));
        assert_eq!(hex::encode(aeskey), "fe697b52bc0d3ce14432ba036a92e65bbb52280990a2fa27883998d72af30161");
    }
}
