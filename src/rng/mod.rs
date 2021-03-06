use rand::prelude::*;
use rand_chacha::ChaChaRng;
use num_bigint::BigUint;

pub struct Rng {

}

impl Rng {
    pub fn new() -> Rng {
        Rng {}
    }

    pub fn generate_bytes(&self, byte_size: usize) -> Vec<u8> {
        let mut rng = ChaChaRng::from_entropy();
        let mut data=vec![0;byte_size];
        rng.fill_bytes(&mut data[..]);
        return data;
    }

    pub fn generate_uint(&self, byte_size: usize) -> BigUint {
        let data = self.generate_bytes(byte_size);
        BigUint::from_bytes_le(&data[..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gen_uint() {
        let rng = Rng::new();
        let data = rng.generate_uint(8);
        println!("{:x}",data);
    }

    #[test]
    fn gen_bytes() {
        let rng = Rng::new();
        let data = rng.generate_bytes(8);
        for v in data.iter() {
            print!("{:x},",v);
        }
        print!("\n");
    }
}