use std::convert::TryInto;
use std::num::Wrapping;

pub fn sha256(input: &[u8]) -> [u8;32] {
    let mut in_pad=input.to_vec();
    let bitlen:u64 = (in_pad.len() as u64)*8;

    // padding
    let pad_size=55 + (if in_pad.len() % 64 > 55 {64} else {0}) - in_pad.len() % 64;
    in_pad.push(0x80);
    for _i in 0..pad_size {
        in_pad.push(0x00);
    }
    in_pad.extend_from_slice(&bitlen.to_be_bytes());

    let (mut a,mut b,mut c,mut d,mut e,mut f,mut g,mut h): (u32,u32,u32,u32,u32,u32,u32,u32);
    let n = in_pad.len()/64;
    let mut w:[u32;64] = [0;64];
    let mut hash:[u32;8];

    const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];

    const H0: [u32; 8] = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];

    hash=H0;

    for i in 0..n {
        let m_block: [u8;64] = in_pad[64*i..64*(i+1)].try_into().unwrap();

        for t in 0..64 {
            if t<16 {
                w[t] = u32::from_be_bytes(m_block[4*t..4*(t+1)].try_into().unwrap());
            } else {
                w[t] = (Wrapping(sigma_1(w[t - 2])) + Wrapping(w[t - 7]) + Wrapping(sigma_0(w[t - 15])) + Wrapping(w[t - 16])).0 & 0xffffffff;
            }
        }

        a=hash[0];
        b=hash[1];
        c=hash[2];
        d=hash[3];
        e=hash[4];
        f=hash[5];
        g=hash[6];
        h=hash[7];

        for t in 0..64 {
            let t1 = (Wrapping(h) + Wrapping(sum_1(e)) + Wrapping(ch(e, f, g)) + Wrapping(K[t]) + Wrapping(w[t])).0 & 0xffffffff;
            let t2 = (Wrapping(sum_0(a)) + Wrapping(maj(a, b, c))).0 & 0xffffffff;
            h = g;
            g = f;
            f = e;
            e = (Wrapping(d) + Wrapping(t1)).0 & 0xffffffff;
            d = c;
            c = b;
            b = a;
            a = (Wrapping(t1) + Wrapping(t2)).0 & 0xffffffff;
        }

        hash[0] = (Wrapping(a) + Wrapping(hash[0])).0 & 0xffffffff;
        hash[1] = (Wrapping(b) + Wrapping(hash[1])).0 & 0xffffffff;
        hash[2] = (Wrapping(c) + Wrapping(hash[2])).0 & 0xffffffff;
        hash[3] = (Wrapping(d) + Wrapping(hash[3])).0 & 0xffffffff;
        hash[4] = (Wrapping(e) + Wrapping(hash[4])).0 & 0xffffffff;
        hash[5] = (Wrapping(f) + Wrapping(hash[5])).0 & 0xffffffff;
        hash[6] = (Wrapping(g) + Wrapping(hash[6])).0 & 0xffffffff;
        hash[7] = (Wrapping(h) + Wrapping(hash[7])).0 & 0xffffffff;
    }

    let mut result:Vec<u8>=Vec::new();

    for v in hash.iter() {
        for u in v.to_be_bytes().iter() {
            result.push(*u);
        }
    }

    result[..].try_into().unwrap()
}

fn rotr(x: u32, n: usize) -> u32 {
    (x >> n) | (x << (32 - n))
}

fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

fn sum_0(x: u32) -> u32 {
    rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)
}

fn sum_1(x: u32) -> u32 {
    rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)
}

fn sigma_0(x: u32) -> u32 {
    rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)
}

fn sigma_1(x: u32) -> u32 {
    rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)
}

#[test]
fn test_sha256() {
    let msg = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".to_string();

    let md = parse_str2bytes("cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1".to_string());

    let digest = sha256(msg.as_bytes());

    for (i,v) in digest.iter().enumerate() {
        assert_eq!(*v,md[i]);
    }
}

#[allow(dead_code)]
fn parse_str2bytes(s: String) -> Vec<u8> {
    let mut b = Vec::new();

    for (i,c) in s.as_str().chars().enumerate() {
        let mut n = c as u8;
        if n >= 0x61 {
            n = n - 0x61 + 0x0A;
        } else {
            n -= 0x30;
        }

        if i%2==0 {
            b.push(n << 4);
        } else {
            *b.last_mut().unwrap() += n;
        }
    }

    b
}