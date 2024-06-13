use crate::crypto::AES;
use crate::crypto::RC4;
pub enum Cipher {
    AES128,
    AES256,
    RC4
}

impl Cipher {
    pub fn from_etype(etype: usize) -> Option<Self> {
        match etype {
            17 => Some(Cipher::AES128),
            18 => Some(Cipher::AES256),
            23 => Some(Self::RC4),
            _ => None
        }
    }

    pub fn etype(&self) -> i32 {
        match self {
            Cipher::AES128 => 17,
            Cipher::AES256 => 18,
            Cipher::RC4 => 23
        }
    }

    pub fn string2key(&self, password: &[u8], salt: &[u8], iteration: Option<u32>) -> Vec<u8> {
        match self {
            Cipher::AES128 => AES::AES128.string2key(password, salt, iteration),
            Cipher::AES256 => AES::AES256.string2key(password, salt, iteration),
            Cipher::RC4 => RC4::string2key(password)
        }
    }

    pub fn encrypt(self, key: &[u8], keyusage: u8, plaintext: &[u8]) -> Vec<u8> {
        match self {
            Cipher::AES128 => AES::AES128.encrypt_with_usage(key, keyusage, plaintext),
            Cipher::AES256 => AES::AES256.encrypt_with_usage(key, keyusage, plaintext),
            Cipher::RC4 => RC4::encrypt(key, keyusage, plaintext)
        }
    }

    pub fn decrypt(&self, key: &[u8], keyusage: u8, ciphertext: &[u8]) -> Vec<u8> {
        match self {
            Cipher::AES128 => AES::AES128.decrypt_with_usage(key, keyusage, ciphertext),
            Cipher::AES256 => AES::AES256.decrypt_with_usage(key, keyusage, ciphertext),
            Cipher::RC4 => RC4::decrypt(key, keyusage, ciphertext)
        }
    }
}
