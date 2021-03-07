use std::convert::TryInto;

/// Advanced Encryption Standard
#[derive(Clone)]
pub struct AES {
    keylen: KeyLength,
    mode: CipherMode,
    nk: usize,
    nr: usize,
    nb: usize,
}

/// Block cipher modes of operation
#[derive(Copy,Clone)]
pub enum CipherMode {
    EBC,
    CBC,
    CFB,
    OFB,
    CTR,
}

/// Key length
#[derive(Copy,Clone)]
pub enum KeyLength {
    KL128 = 128,
    KL192 = 192,
    KL256 = 256,
}

impl AES {
    pub fn new(keylen: KeyLength, mode: CipherMode) -> Self {
        let nk=(keylen as usize)/32;
        let nr=nk+6;
        
        AES {keylen,mode,nk,nr,nb:4}
    }

    pub fn encrypt(&self, key: &[u8], iv: &[u8;16], plain: &[u8]) -> Result<Vec<u8>,&'static str> {
        if key.len()!=(self.keylen as usize)/8 {
            return Err("Invalid key length");
        }

        if iv.len()!=128/8 {
            return Err("Invalid IV length");
        }

        if plain.len()%16!=0 {
            return Err("Plain text must be padded in 16-byte units");
        }

        if plain.len()==0 {
            return Err("Empty plain text");
        }

        let mut cipher:Vec<u8>=Vec::with_capacity(plain.len()+1);
        let mut plain_block: [u8;16];
        let mut cipher_block: [u8;16]=[0;16];
        let mut block: [u8;16]=[0;16];
        let mut out_block: [u8;16]=[0;16];
        let mut nonce: [u8;16]=[0;16];
        
        for i in 0..plain.len()/16 {
            plain_block = plain[16*i..16*(i+1)].try_into().unwrap();

            match self.mode {
                CipherMode::EBC=>{
                    cipher_block = self.encrypt_block(key,&plain_block);
                },
                CipherMode::CBC=>{
                    if i==0 {
                        for j in 0..16 {
                            block[j]=plain_block[j]^iv[j];
                        }
                    } else {
                        for j in 0..16 {
                            block[j]=plain_block[j]^cipher_block[j];
                        }
                    }
                    
                    cipher_block = self.encrypt_block(key,&block);
                },
                CipherMode::CFB=>{
                    if i==0 {
                        block = self.encrypt_block(key,&iv);
                    } else {
                        block = self.encrypt_block(key,&cipher_block);
                    }

                    for j in 0..16 {
                        cipher_block[j]=block[j]^plain_block[j];
                    }
                },
                CipherMode::OFB=>{
                    if i==0 {
                        block=*iv;
                    } else {
                        block = out_block;
                    }
                    out_block = self.encrypt_block(key,&block);
                    
                    for j in 0..16 {
                        cipher_block[j]=plain_block[j]^out_block[j];
                    }
                },
                CipherMode::CTR=>{
                    if i==0 {
                        nonce=*iv;
                    }
                    block = self.encrypt_block(key,&nonce);
                    for j in 0..16 {
                        cipher_block[j]=block[j]^plain_block[j];
                    }

                    // increment nonce
                    for i in 0..16 {
                        if nonce[i]!=0xFF {
                            nonce[i]+=1;
                            break;
                        } else {
                            nonce[i]=0;
                        }
                    }
                },
            }

            cipher.extend_from_slice(&cipher_block);
        }

        Ok(cipher)
    }

    pub fn decrypt(&self, key: &[u8],  iv: &[u8;16], cipher: &[u8]) -> Result<Vec<u8>,&'static str> {
        if key.len()!=(self.keylen as usize)/8 {
            return Err("Invalid key length");
        }

        if iv.len()!=128/8 {
            return Err("Invalid IV length");
        }

        if cipher.len()%16!=0 {
            return Err("Invalid ciphertext length");
        }
        
        let mut plain:Vec<u8>=Vec::with_capacity(cipher.len()+1);
        let mut plain_block: [u8;16]=[0;16];
        let mut cipher_block: [u8;16];
        let mut block: [u8;16];
        let mut out_block: [u8;16]=[0;16];
        let mut nonce: [u8;16]=[0;16];
        
        for i in 0..cipher.len()/16 {
            cipher_block = cipher[16*i..16*(i+1)].try_into().unwrap();

            match self.mode {
                CipherMode::EBC=>{
                    plain_block = self.decrypt_block(key,&cipher_block);
                },
                CipherMode::CBC=>{
                    block = self.decrypt_block(key,&cipher_block);

                    if i==0 {
                        for j in 0..16 {
                            plain_block[j]=block[j]^iv[j];
                        }
                    } else {
                        for j in 0..16 {
                            plain_block[j]=block[j]^cipher_block[j];
                        }
                    }
                },
                CipherMode::CFB=>{
                    if i==0 {
                        block = self.encrypt_block(key,&iv);
                    } else {
                        block = self.encrypt_block(key,&cipher_block);
                    }
                    
                    for j in 0..16 {
                        plain_block[j]=block[j]^cipher_block[j];
                    }
                },
                CipherMode::OFB=>{
                    if i==0 {
                        block=*iv;
                    } else {
                        block = out_block;
                    }
                    out_block = self.encrypt_block(key,&block);
                    
                    for j in 0..16 {
                        plain_block[j]=cipher_block[j]^out_block[j];
                    }
                },
                CipherMode::CTR=>{
                    if i==0 {
                        nonce=*iv;
                    }
                    block = self.encrypt_block(key,&nonce);
                    for j in 0..16 {
                        plain_block[j]=block[j]^cipher_block[j];
                    }

                    // increment nonce
                    for i in 0..16 {
                        if nonce[i]!=0xFF {
                            nonce[i]+=1;
                            break;
                        } else {
                            nonce[i]=0;
                        }
                    }
                },
            }

            plain.extend_from_slice(&plain_block);
        }

        Ok(plain)
    }

    pub fn encrypt_block(&self, key: &[u8], input: &[u8;16]) -> [u8;16] {
        assert!(key.len()==16 || key.len()==24 || key.len()==32, "Invalid key length!");

        let mut state: [[u8; 4]; 4] = [[0; 4]; 4];

        for (i,v) in input.iter().enumerate() {
            state[i%4][i/4]=*v;
        }

        let rkey = self.expand_key(&key);
        self.add_roundkey(&mut state,&rkey,0);
        for i in 1..self.nr {
            for row in state.iter_mut() {
                for v in row.iter_mut() {
                    *v = AES::sub_bytes(*v);
                }
            }
            state = AES::shift_rows(&state);
            state = AES::mix_columns(&state);
            self.add_roundkey(&mut state,&rkey,i);
        }
        for row in state.iter_mut() {
            for v in row.iter_mut() {
                *v = AES::sub_bytes(*v);
            }
        }
        state = AES::shift_rows(&state);
        self.add_roundkey(&mut state,&rkey,self.nr);

        let mut i=0;
        let mut j=0;
        let mut output: [u8; 16] = [0; 16];
        for v1 in state.iter() {
            for v2 in v1.iter() {
                output[4*i+j]=*v2;
                i+=1;
            }
            i=0;
            j+=1;
        }

        output
    }

    pub fn decrypt_block(&self, key: &[u8], input: &[u8;16]) -> [u8;16] {
        assert!(key.len()==16 || key.len()==24 || key.len()==32, "Invalid key length!");

        let mut state: [[u8; 4]; 4] = [[0; 4]; 4];

        for (i,v) in input.iter().enumerate() {
            state[i%4][i/4]=*v;
        }

        let rkey = self.expand_key(&key);
        self.add_roundkey(&mut state,&rkey,self.nr);
        for i in (1..self.nr).rev() {
            state = AES::inv_shift_rows(&state);
            for row in state.iter_mut() {
                for v in row.iter_mut() {
                    *v = AES::inv_sub_bytes(*v);
                }
            }
            self.add_roundkey(&mut state,&rkey,i);
            state = AES::inv_mix_columns(&state);
        }
        state = AES::inv_shift_rows(&state);
        for row in state.iter_mut() {
            for v in row.iter_mut() {
                *v = AES::inv_sub_bytes(*v);
            }
        }
        self.add_roundkey(&mut state,&rkey,0);

        let mut i=0;
        let mut j=0;
        let mut output: [u8; 16] = [0; 16];
        for v1 in state.iter() {
            for v2 in v1.iter() {
                output[4*i+j]=*v2;
                i+=1;
            }
            i=0;
            j+=1;
        }

        output
    }

    // Round key functions
    fn expand_key(&self, key: &[u8]) -> Vec<u32> {
        assert!(key.len()==128/8||key.len()==192/8||key.len()==256/8,"Invalid key length!");

        let nk = self.nk;
        let nr = self.nr;
        let nb = self.nb;
        const RCON: [u32;11]=[
            0x00000000, /* invalid */
            0x00000001, /* x^0 */
            0x00000002, /* x^1 */
            0x00000004, /* x^2 */
            0x00000008, /* x^3 */
            0x00000010, /* x^4 */
            0x00000020, /* x^5 */
            0x00000040, /* x^6 */
            0x00000080, /* x^7 */
            0x0000001B, /* x^4 + x^3 + x^1 + x^0 */
            0x00000036, /* x^5 + x^4 + x^2 + x^1 */];

        let mut w: Vec<u32> = vec![0; nb * (nr + 1)];

        for i in 0..nk {
            w[i]=u32::from_le_bytes(key[4*i..4*i+4].try_into().unwrap());
        }

        for i in nk..nb*(nr+1) {
            let mut temp=w[i-1];
            if i%nk == 0 {
                temp = AES::sub_word(AES::rot_word(temp)) ^ RCON[i/nk];
            } else if 6 < nk && i%nk == 4 {
                temp = AES::sub_word(temp);
            }
            w[i]=w[i-nk] ^ temp;
        }

        w
    }

    fn rot_word(w: u32) -> u32 {
        (w<<8)+(w>>24)
    }

    fn sub_word(w: u32) -> u32 {
        let mut r:u32 = 0;
        for i in 0..4 {
            r |= (AES::sub_bytes((w>>i*8 & 0xFF) as u8) as u32) << i*8;
        }
        r
    }

    fn sub_bytes(input: u8) -> u8 {
        const SBOX_TABLE: [u8;256] = [0x63,  0x7c,  0x77,  0x7b,  0xf2,  0x6b,  0x6f,  0xc5,  0x30,  0x01,  0x67,  0x2b,  0xfe,  0xd7,  0xab,  0x76,
                                    0xca,  0x82,  0xc9,  0x7d,  0xfa,  0x59,  0x47,  0xf0,  0xad,  0xd4,  0xa2,  0xaf,  0x9c,  0xa4,  0x72,  0xc0,
                                    0xb7,  0xfd,  0x93,  0x26,  0x36,  0x3f,  0xf7,  0xcc,  0x34,  0xa5,  0xe5,  0xf1,  0x71,  0xd8,  0x31,  0x15,
                                    0x04,  0xc7,  0x23,  0xc3,  0x18,  0x96,  0x05,  0x9a,  0x07,  0x12,  0x80,  0xe2,  0xeb,  0x27,  0xb2,  0x75,
                                    0x09,  0x83,  0x2c,  0x1a,  0x1b,  0x6e,  0x5a,  0xa0,  0x52,  0x3b,  0xd6,  0xb3,  0x29,  0xe3,  0x2f,  0x84,
                                    0x53,  0xd1,  0x00,  0xed,  0x20,  0xfc,  0xb1,  0x5b,  0x6a,  0xcb,  0xbe,  0x39,  0x4a,  0x4c,  0x58,  0xcf,
                                    0xd0,  0xef,  0xaa,  0xfb,  0x43,  0x4d,  0x33,  0x85,  0x45,  0xf9,  0x02,  0x7f,  0x50,  0x3c,  0x9f,  0xa8,
                                    0x51,  0xa3,  0x40,  0x8f,  0x92,  0x9d,  0x38,  0xf5,  0xbc,  0xb6,  0xda,  0x21,  0x10,  0xff,  0xf3,  0xd2,
                                    0xcd,  0x0c,  0x13,  0xec,  0x5f,  0x97,  0x44,  0x17,  0xc4,  0xa7,  0x7e,  0x3d,  0x64,  0x5d,  0x19,  0x73,
                                    0x60,  0x81,  0x4f,  0xdc,  0x22,  0x2a,  0x90,  0x88,  0x46,  0xee,  0xb8,  0x14,  0xde,  0x5e,  0x0b,  0xdb,
                                    0xe0,  0x32,  0x3a,  0x0a,  0x49,  0x06,  0x24,  0x5c,  0xc2,  0xd3,  0xac,  0x62,  0x91,  0x95,  0xe4,  0x79,
                                    0xe7,  0xc8,  0x37,  0x6d,  0x8d,  0xd5,  0x4e,  0xa9,  0x6c,  0x56,  0xf4,  0xea,  0x65,  0x7a,  0xae,  0x08,
                                    0xba,  0x78,  0x25,  0x2e,  0x1c,  0xa6,  0xb4,  0xc6,  0xe8,  0xdd,  0x74,  0x1f,  0x4b,  0xbd,  0x8b,  0x8a,
                                    0x70,  0x3e,  0xb5,  0x66,  0x48,  0x03,  0xf6,  0x0e,  0x61,  0x35,  0x57,  0xb9,  0x86,  0xc1,  0x1d,  0x9e,
                                    0xe1,  0xf8,  0x98,  0x11,  0x69,  0xd9,  0x8e,  0x94,  0x9b,  0x1e,  0x87,  0xe9,  0xce,  0x55,  0x28,  0xdf,
                                    0x8c,  0xa1,  0x89,  0x0d,  0xbf,  0xe6,  0x42,  0x68,  0x41,  0x99,  0x2d,  0x0f,  0xb0,  0x54,  0xbb,  0x16];
        
        SBOX_TABLE[input as usize]
    }
    
    fn inv_sub_bytes(input: u8) -> u8 {
        const INV_SBOX_TABLE: [u8;256] = [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
                                        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
                                        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
                                        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
                                        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
                                        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
                                        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
                                        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
                                        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
                                        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
                                        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
                                        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
                                        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
                                        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
                                        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
                                        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,];
        
        INV_SBOX_TABLE[input as usize]
    }

    // Block ecnryption functions
    fn add_roundkey(&self,state: &mut [[u8;4];4], round_key:&[u32], round: usize) {
        let l = round*self.nb;

        for c in 0..4 {
            let sb=[state[0][c], state[1][c], state[2][c], state[3][c]];
            let sw = (round_key[l+c]^u32::from_le_bytes(sb)).to_le_bytes();
            for i in 0..4 {
                state[i][c]=sw[i];
            }
        }
    }

    fn shift_rows(state: &[[u8; 4]; 4]) -> [[u8;4];4] {
        let mut res=[[0;4];4];
        for i in 0..4 {
            for j in 0..4 {
                res[i][j] = state[i][(j+i)%4];
            }
        }

        res
    }
    
    fn inv_shift_rows(state: &[[u8; 4]; 4]) -> [[u8;4];4] {
        let mut res=[[0;4];4];
        for i in 0..4 {
            for j in 0..4 {
                res[i][j] = state[i][(j+4-i)%4];
            }
        }

        res
    }

    fn mix_columns(state: &[[u8;4];4]) -> [[u8;4];4] {
        let matrix = [
            [0x02, 0x03, 0x01, 0x01],
            [0x01, 0x02, 0x03, 0x01],
            [0x01, 0x01, 0x02, 0x03],
            [0x03, 0x01, 0x01, 0x02]];

        let mut res:[[u8;4];4]=[[0;4];4];

        for i in 0..4 {
            for j in 0..4 {
                res[j][i]=0;
                for k in 0..4 {
                    res[j][i]^=AES::galois_mul(matrix[j][k], state[k][i])
                }
            }
        }

        res
    }
    
    fn inv_mix_columns(state: &[[u8;4];4]) -> [[u8;4];4] {
        let matrix = [
            [0x0e, 0x0b, 0x0d, 0x09],
            [0x09, 0x0e, 0x0b, 0x0d],
            [0x0d, 0x09, 0x0e, 0x0b],
            [0x0b, 0x0d, 0x09, 0x0e]];

        let mut res:[[u8;4];4]=[[0;4];4];

        for i in 0..4 {
            for j in 0..4 {
                res[j][i]=0;
                for k in 0..4 {
                    res[j][i]^=AES::galois_mul(matrix[j][k], state[k][i])
                }
            }
        }

        res
    }

    fn galois_mul(mut a: u8, b:u8) -> u8{
        let mut mask: u8 = 0x01;
        let mut p: u8 = 0;
        
        loop {
            if mask == 0 {
                break
            }

            if b & mask != 0 {
                p^=a;
            }
            a=AES::xtime(a);

            mask<<=1;
        }

        p
    }

    fn xtime(b:u8) -> u8 {
        (b<<1) ^ (if b&0x80!=0 {0x1b} else {0x00})
    }
}