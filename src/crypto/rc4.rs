use md4::{Md4, Digest};
use crate::crypto::gen_random_bytes;
use hmac::{Mac, Hmac};
use md5::Md5;
use rc4::Rc4;
use rc4::{KeyInit, StreamCipher};

pub struct RC4 {
}

impl RC4 {
    pub fn string2key(password: &[u8]) -> Vec<u8> {
        let mut password_utf16le = Vec::new();
        std::str::from_utf8(password)
            .unwrap()
            .encode_utf16()
            .for_each(|x | {
                password_utf16le.push((x & 0xff) as u8);
                password_utf16le.push((x >> 8) as u8);
            });
        let mut hasher = <Md4 as Digest>::new();
        hasher.update(&password_utf16le);
        hasher.finalize()[..].to_vec()
    }

    pub fn encrypt(key: &[u8], keyusage: u8, plaintext: &[u8]) -> Vec<u8> {
        let key_usage = (keyusage as u32).to_le_bytes();
        let mut confounder = gen_random_bytes(8);

        confounder.append(&mut plaintext.to_vec());

        // Generate checksum key: Ki
        let ki = md5_hmac(key, &key_usage);

        // calculate checksum using key: Ki
        let mut checksum = md5_hmac(&ki, &confounder);

        // Generate encryption key: Ke
        let ke = md5_hmac(&ki, &checksum);

        // Perform encryption using key: Ke
        let ke_bytes = TryInto::<&[u8; 16]>::try_into(&ke[..16]).unwrap();
        let mut encryptor = Rc4::new(ke_bytes.into());
        encryptor.apply_keystream(&mut confounder);

        let mut ciphertext = Vec::new();
        ciphertext.append(&mut checksum);
        ciphertext.append(&mut confounder);
        ciphertext
    }

    pub fn decrypt(key: &[u8], keyusage: u8, ciphertext: &[u8]) -> Vec<u8> {
        let key_usage = (keyusage as u32).to_le_bytes();
        let cksum = &ciphertext[..16];
        let mut ct = ciphertext[16..].to_vec();

        let ki = md5_hmac(key, &key_usage);
        let ke = md5_hmac(&ki, cksum);

        let ke_bytes = TryInto::<&[u8; 16]>::try_into(&ke[..16]).unwrap();
        let mut decryptor = Rc4::new(ke_bytes.into());
        decryptor.apply_keystream(&mut ct);
        let expected_cksum = md5_hmac(&ki, &ct);
        if expected_cksum == cksum {
            println!("Checksum matched!");
        }
        ct[8..].to_vec()
    }
} 

fn md5_hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    type Md5Hmac = Hmac<Md5>;
    
    let mut hasher = <Md5Hmac as Mac>::new_from_slice(key.into())
        .unwrap();
    hasher.update(data);
    hasher
        .finalize()
        .into_bytes()
        .to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rcstring() {
        let key = RC4::string2key(b"foo");
        let expected_key = [
            0xac, 0x8e, 0x65, 0x7f, 0x83, 0xdf, 0x82, 0xbe,
            0xea, 0x5d, 0x43, 0xbd, 0xaf, 0x78, 0x00, 0xcc
        ];
        assert_eq!(key, expected_key.to_vec());
    }

    #[test]
    fn rcencdec() {
        let key = RC4::string2key(b"foo");
        let data = b"drdragon79".to_vec();
        let ct = RC4::encrypt(&key, 1, &data);
        let pt = RC4::decrypt(&key, 1, &ct);
        assert_eq!(data, pt);
    }
}
