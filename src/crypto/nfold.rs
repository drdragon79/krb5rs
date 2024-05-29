pub fn nfold(bytes: &[u8], n: usize) -> Vec<u8> {
    let mut storage: Vec<u8> = Vec::new();
    let lcm = lcm(n, bytes.len());
    for i in 0..lcm/bytes.len() {
        let mut rotated_bytes = rotate(bytes, 13 * i);
        storage.append(&mut rotated_bytes);
    }
    storage
        .chunks(n)
        .map(|x| {
            x.to_vec()
        })
        .reduce(|a, b| {
            add(&a, &b)
        })
        .unwrap()
}

fn rotate(bytes: &[u8], rot: usize) -> Vec<u8> {
    let mut char_repr = bytes
        .iter()
        .map(|x|{
            format!("{:08b}", *x)
        })
        .collect::<String>()
        .chars()
        .collect::<Vec<char>>();
    let len = char_repr.len();
    char_repr.rotate_right(rot % len);
    char_repr
        .chunks(8)
        .map(|x| {
            x
                .iter()
                .collect::<String>()
        })
        .map(|x| {
            usize::from_str_radix(x.as_str(), 2).unwrap() as u8
        })
        .collect()
}

fn add(one: &[u8], two: &[u8]) -> Vec<u8> {
    let n = one.len();
    let sum = one.to_vec();
    let mut sum = sum
        .iter()
        .enumerate()
        .map(|(a, b)| {
            *b as u16 + two[a] as u16
        })
        .collect::<Vec<u16>>();
    // check bit size
    while sum
        .iter()
        .any(|x| {
            *x & !0xff != 0
        }) {
            sum = (0..n)
                .map(|i| {
                    ((sum[(i + 1) % n] >> 8) + (sum[i] & 0xff)) as u16
                })
                .collect();
        }
    sum.
        iter()
        .map(|x| *x as u8)
        .collect()
}

fn lcm(a: usize, b: usize) -> usize {
    let gcd = gcd(a, b);
    (a * b) / gcd
}

fn gcd(a: usize, b: usize) -> usize {
    if b == 0 {
        a
    } else {
        gcd(b, a % b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gcd1() {
        assert_eq!(gcd(36, 60), 12)
    }
    #[test]
    fn test_gcd2() {
        assert_eq!(gcd(60, 36), 12)
    }
    #[test]
    fn test_lcm1() {
        assert_eq!(lcm(12, 18), 36)
    }
    #[test]
    fn test_lcm2() {
        assert_eq!(lcm(4, 1), 4)
    }
    #[test]
    fn test_rotation() {
        let rotated = rotate(&[1,2,3,4], 13);
        assert_eq!(rotated, vec![24, 32, 8, 16])
    }
    #[test]
    fn test_rotation2() {
        let rotated = rotate(&[24, 32, 8, 16], 13);
        assert_eq!(rotated, vec![64, 128, 193, 0])
    }
    // #[test]
    // fn test_nfold() {
    //     nfold(b"\x01\x02\x03\x04", 5);
    // }
    #[test]
    fn test_add1() {
        assert_eq!(add(&[1,2,3], &[2,3,4]), vec![3,5,7]);
    }
    #[test]
    fn test_add2() {
        assert_eq!(add(&[0xff, 0xff, 0x00], &[0x00, 0x01, 0x00]), vec![0x00, 0x00, 0x01]);
    }
    #[test]
    fn test_add3() {
        assert_eq!(add(&[0xff, 0xff, 0xff], &[0x00, 0x00, 0x01]), vec![0x00, 0x00, 0x01]);
    }
    #[test]
    fn test_add4() {
        assert_eq!(add(&[0x00, 0xff, 0xff], &[0x00, 0x00, 0x01]), vec![0x01, 0x00, 0x00]);
    }

    // RFC Test cases
    #[test]
    fn test_64_fold() {
        let res = nfold(b"012345", 64/8);
        let res = hex::encode(&res);
        assert_eq!(res, String::from("be072631276b1955"));
    }
    #[test]
    fn test_64_fold2() {
        let res = nfold(b"password", 56/8);
        let res = hex::encode(&res);
        assert_eq!(res, String::from("78a07b6caf85fa"));
    }
    #[test]
    fn test_64_fold3() {
        let res = nfold(b"Rough Consensus, and Running Code", 64/8);
        let res = hex::encode(&res);
        assert_eq!(res, String::from("bb6ed30870b7f0e0"));
    }
    #[test]
    fn test_64_fold4() {
        let res = nfold(b"password", 168/8);
        let res = hex::encode(&res);
        assert_eq!(res, String::from("59e4a8ca7c0385c3c37b3f6d2000247cb6e6bd5b3e"));
    }
    #[test]
    fn test_64_fold5() {
        let res = nfold(b"MASSACHVSETTS INSTITVTE OF TECHNOLOGY", 192/8);
        let res = hex::encode(&res);
        assert_eq!(res, String::from("db3b0d8f0b061e603282b308a50841229ad798fab9540c1b"));
    }
    #[test]
    fn test_64_fold6() {
        let res = nfold(b"Q", 168/8);
        let res = hex::encode(&res);
        assert_eq!(res, String::from("518a54a215a8452a518a54a215a8452a518a54a215"));
    }
    #[test]
    fn test_64_fold7() {
        let res = nfold(b"ba", 168/8);
        let res = hex::encode(&res);
        assert_eq!(res, String::from("fb25d531ae8974499f52fd92ea9857c4ba24cf297e"));
    }
}
