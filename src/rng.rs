use num::BigUint;
use rand::prelude::*;
use rand_chacha::ChaChaRng;

#[derive(Clone)]
pub struct Rng {
    rng: ChaChaRng,
}

impl Rng {
    pub fn new() -> Rng {
        Rng {rng:ChaChaRng::from_entropy()}
    }

    pub fn generate_bytes(&mut self, byte_size: usize) -> Vec<u8> {
        let mut data = vec![0; byte_size];
        self.rng.fill_bytes(&mut data[..]);
        return data;
    }

    pub fn generate_uint(&mut self, byte_size: usize) -> BigUint {
        let data = self.generate_bytes(byte_size);
        BigUint::from_bytes_le(&data[..])
    }
}