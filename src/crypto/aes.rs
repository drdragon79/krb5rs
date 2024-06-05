use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyInit, KeyIvInit, BlockCipher};
use cbc::cipher::block_padding::NoPadding as nopadcbc;
use ecb::cipher::block_padding::NoPadding as nopadecb;
use sha1::Sha1;
use pbkdf2::pbkdf2_hmac;
use log::*;
use crate::crypto::{
    nfold,
    zeropad,
    to_cts,
    xor
};

#[derive(Debug)]
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

    fn from_etype(etype: i32) -> Option<Self> {
        match etype {
            17 => Some(AES::AES128),
            18 => Some(AES::AES256),
            _ => None
        }
    }

    pub fn tk(&self, password: &[u8], salt: &[u8], rounds: u32) -> Vec<u8> {
        debug!("TK <- {:?}|{}|{}|{}", self, hex::encode(password), hex::encode(salt), rounds);
        let mut buff =  [0u8; 256];
        pbkdf2_hmac::<Sha1>(password, salt, rounds, &mut buff);
        let tk = buff[..self.keysize()].to_vec();
        debug!("TK -> {}", hex::encode(&tk));
        tk
    }

    pub fn dk(&self, constant: &[u8], key: &[u8]) -> Vec<u8> {
        debug!("DK <- {:?}|{}|{}", self, hex::encode(constant), hex::encode(key));
        let mut wkconstant = if constant.len() < self.blocksize() {
            nfold(constant, self.blocksize())
        } else {
            constant.to_vec()
        };

        let mut dervivedkey = Vec::new();
        
        while dervivedkey.len() < self.keysize() {
            let key_n = self.encrypt(&wkconstant, key);
            dervivedkey.append(&mut key_n.clone());
            wkconstant = key_n;
        }
        debug!("DK -> {}", hex::encode(&dervivedkey));
        dervivedkey
    }

    pub fn encrypt(&self, plaintext: &[u8], key: &[u8]) -> Vec<u8> {
        match self {
            AES::AES128 => encrypt_cts::<aes::Aes128>(plaintext, key, self.blocksize()),
            AES::AES256 => encrypt_cts::<aes::Aes256>(plaintext, key, self.blocksize())
        }
    }

    pub fn decrypt(&self, ciphertext: &[u8], key: &[u8]) -> Vec<u8> {
        match self {
            AES::AES128 => decrypt_cts::<aes::Aes128>(ciphertext, key, self.blocksize()),
            AES::AES256 => decrypt_cts::<aes::Aes256>(ciphertext, key, self.blocksize())
        }
    }

    pub fn string2key(&self,password: &[u8], salt: &[u8], iteration: Option<u32>) -> Vec<u8> {
        let rounds = iteration
            .unwrap_or(4096);
        let tkey = self.tk(password, salt, rounds);
        self.dk(b"kerberos", &tkey)
    }
} 

fn decrypt_cts<T>(ciphertext: &[u8], key: &[u8], blocksize: usize) -> Vec<u8> 
where T: BlockCipher + BlockDecryptMut + KeyInit + Clone {
    debug!("DECRYPT_CTS <- {:?}|{}|{}", "test", hex::encode(ciphertext), hex::encode(key));

    let ct_split = ciphertext
        .chunks(16)
        .map(|x| {
            x.to_vec()
        })
        .collect::<Vec<Vec<u8>>>();

    let mut plaintext = ct_split.clone();

    let mut iv = vec![0u8; blocksize];

    let splitlen = plaintext.len();

    let decryptor = <ecb::Decryptor::<T> as KeyInit>::new(key.into());
    if splitlen == 1 {
        let _ = decryptor.clone().decrypt_padded_mut
            ::<nopadecb>
            (&mut plaintext[0]);
    } else {
        // decrypt till 3rd to last block
        for block in &mut plaintext[..(splitlen - 2)] {
            let next_iv = block.clone();
            let _ = decryptor.clone().decrypt_padded_mut
                ::<nopadecb>
                (block);
            *block = xor(block.as_ref(), &iv);
            iv = next_iv;
        }
        // second last block
        let lastblocklen = plaintext[splitlen - 1].len();
        let secondlastblock = &mut plaintext[splitlen - 2];
        let _ = decryptor.clone().decrypt_padded_mut
            ::<nopadecb>
            (secondlastblock);
        let lastblockref = ct_split[splitlen - 1].clone();
        let mut leftover = secondlastblock[lastblocklen..].to_vec();
        *secondlastblock = xor(&secondlastblock[..lastblocklen], &lastblockref);

        // last block
        let lastblock = &mut plaintext[splitlen - 1];
        lastblock.append(&mut leftover);
        let _ = decryptor.clone().decrypt_padded_mut
            ::<nopadecb>
            (lastblock);
        *lastblock = xor(&lastblock, &iv);

        // Swap last two blocks
        plaintext.swap(splitlen - 2, splitlen - 1);
    }
    plaintext
        .into_iter()
        .flatten()
        .collect::<Vec<u8>>()
}


fn encrypt_cts<T>(plaintext: &[u8], key: &[u8], blocksize: usize) -> Vec<u8> 
where T: BlockCipher + BlockEncryptMut + KeyInit
    {
    debug!("ENCRYPT_CTS <- {:?}|{}|{}", "test", hex::encode(plaintext), hex::encode(key));
    let original_plaintext_len = plaintext.len();
    let mut padded_plaintext = zeropad(plaintext, blocksize);

    let iv =  vec![0u8; blocksize];

    let plaintext_len = padded_plaintext.len();

    let encryptor = <cbc::Encryptor::<T> as KeyIvInit>::new(key.into(), iv[..].into());
    let ciphertext = encryptor.encrypt_padded_mut
        ::<nopadcbc>
        (&mut padded_plaintext, plaintext_len)
        .unwrap_or_else(|e| {
            error!("Encryption Error <PadError>: {}", e);
            std::process::exit(0);
        });
    let ciphertext = ciphertext.to_vec();
    debug!("ENCRYPT_CTS:ciphertext: {:x?}", hex::encode(&ciphertext));
    let cts_ciphertext = to_cts(
        &ciphertext,
        original_plaintext_len,
        blocksize
    );
    debug!("ENCRYPT_CTS -> {}", hex::encode(&cts_ciphertext));
    cts_ciphertext
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init() {
        let _ = env_logger::builder().try_init();
    }

    #[test]
    fn test_tk1() {
        init();
        let aes128= AES::AES128;
        let result  = aes128.tk(b"password", b"ATHENA.MIT.EDUraeburn", 1);
        let result = hex::encode(result);
        let expected = "cdedb5281bb2f801565a1122b2563515".to_string();
        assert_eq!(result, expected);
    }
    #[test]
    fn test_tk2() {
        init();
        let aes256 = AES::AES256;
        let result  = aes256.tk(b"password", b"ATHENA.MIT.EDUraeburn", 1);
        let result = hex::encode(result);
        let expected = "cdedb5281bb2f801565a1122b25635150ad1f7a04bb9f3a333ecc0e2e1f70837".to_string();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_string2key1() {
        init();
        let aes = AES::AES128;
        let aeskey = aes.string2key(b"password", b"ATHENA.MIT.EDUraeburn", Some(1));
        assert_eq!(hex::encode(aeskey), "42263c6e89f4fc28b8df68ee09799f15");
    }
    #[test]
    fn test_string2key2() {
        init();
        let aes = AES::AES256;
        let aeskey = aes.string2key(b"password", b"ATHENA.MIT.EDUraeburn", Some(1));
        assert_eq!(hex::encode(aeskey), "fe697b52bc0d3ce14432ba036a92e65bbb52280990a2fa27883998d72af30161");
    }

    #[test]
    fn logger_test() {
        init();
        let plaintext = b"this is a random test to test ecnrytpion scene of the AES";
        let key = hex::decode("42263c6e89f4fc28b8df68ee09799f15").unwrap();
        let aes = AES::AES128;
        let finalct = aes.encrypt(plaintext, &key);
        let pt  = aes.decrypt(&finalct, &key);
        assert_eq!(plaintext.to_vec(), pt);
    }
}
