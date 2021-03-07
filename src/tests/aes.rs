#[cfg(test)]
mod tests {
    use crate::rng::Rng;
    use crate::aes::{CipherMode, KeyLength, TryInto, AES};

    #[test]
    fn xtime() {
        assert_eq!(AES::xtime(0b10010000),0b00111011);
    }

    #[test]
    fn galois_mul() {
        assert_eq!(AES::galois_mul(0b10101100, 0b00100100),0b11011010)
    }

    #[test]
    fn expand_key() {
        let r = Rng::new();
        let bs = r.generate_bytes(16);

        let aes = AES::new(KeyLength::KL128, CipherMode::CBC);
        let ek = aes.expand_key(&bs[..]);
        let mut es=Vec::new();
        for v in ek.iter() {
            es.append(&mut v.to_le_bytes().to_vec());
        }
        for i in 0..bs.len() {
            assert_eq!(bs[i],es[i]);
        }
    }

    #[test]
    fn sub_bytes() {
        for i in 0..0xFF {
            assert_eq!(AES::inv_sub_bytes(AES::sub_bytes(i as u8)),i as u8);
        }
    }

    #[test]
    fn shift_rows() {
        let mut state = [[0x0,0x1,0x2,0x3],
                    [0x4,0x5,0x6,0x7],
                    [0x8,0x9,0xA,0xB],
                    [0xC,0xD,0xE,0xF]];
        let prev = state;

        state = AES::inv_shift_rows(&AES::shift_rows(&state));

        assert_eq!(state,prev);
    }

    #[test]
    fn mix_columns() {
        let mut state = [[0x0,0x1,0x2,0x3],
                    [0x4,0x5,0x6,0x7],
                    [0x8,0x9,0xA,0xB],
                    [0xC,0xD,0xE,0xF]];
        let prev = state;

        state = AES::inv_mix_columns(&AES::mix_columns(&state));

        assert_eq!(state,prev);
    }

    #[test]
    fn encrypt_block() {
        let aes = AES::new(KeyLength::KL128,CipherMode::EBC);
        let input:[u8;16]=[0;16];
        let key:[u8;16]=[0;16];
        let en = aes.encrypt_block(&key,&input);
        let de = aes.decrypt_block(&key,&en);

        assert_eq!(input,de);
    }

    #[test]
    fn aes() {
        let aes = AES::new(KeyLength::KL256, CipherMode::CBC);
        let rnd = Rng::new();
        let input:Vec<u8> = (0..16).collect();
        let key=rnd.generate_bytes(256/8);
        let iv=rnd.generate_bytes(16);
        let en = aes.encrypt(&key, &iv.clone().try_into().unwrap(), &input[..]).unwrap();
        let de = aes.decrypt(&key, &iv.try_into().unwrap(), &en).unwrap();

        for i in 0..input.len() {
            assert_eq!(input[i],de[i]);
        }
    }
}