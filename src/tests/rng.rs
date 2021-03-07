#[cfg(test)]
mod tests {
    use crate::rng::Rng;

    #[test]
    fn gen_uint() {
        let mut rng = Rng::new();
        let data = rng.generate_uint(8);
        println!("{:x}", data);
    }

    #[test]
    fn gen_bytes() {
        let mut rng = Rng::new();
        let data = rng.generate_bytes(8);
        for v in data.iter() {
            print!("{:x},", v);
        }
        print!("\n");
    }
}
