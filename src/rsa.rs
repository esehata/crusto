use crate::prime;
use num::{BigUint,BigInt,bigint::{ToBigInt,Sign},Zero,One};
use num::Integer;


pub struct PublicKey {
    n: BigUint,
    e: BigUint
}

pub struct PrivateKey {
    p: BigUint,
    q: BigUint,
    d: BigUint,
}

pub fn gen_key() -> (PublicKey, PrivateKey) {
    let e = BigUint::from(65537u32);
    let mut p = prime::gen_prime(1024);
    let mut q = prime::gen_prime(1024);

    while p.clone() % e.clone() == BigUint::one() {
        p = prime::gen_prime(1024);
    }
    while q.clone() % e.clone() == BigUint::one() {
        q = prime::gen_prime(1024);
    }

    let n = p.clone()*q.clone();
    let phi = (p.clone()-1u8)*(q.clone()-1u8);

    let exgcd = BigInt::extended_gcd(&BigInt::from_biguint(Sign::Plus, e.clone()),&BigInt::from_biguint(Sign::Plus, phi.clone()));
    let (_,d) = ((exgcd.x + BigInt::from_biguint(Sign::Plus, phi.clone())) % BigInt::from_biguint(Sign::Plus, phi.clone())).into_parts();

    (PublicKey{n,e},PrivateKey{p,q,d})
}

pub fn gen_pubkey(sk: &PrivateKey) -> PublicKey {
    let phi = (sk.p.clone()-1u8)*(sk.q.clone()-1u8);
    
    let exgcd = BigInt::extended_gcd(&BigInt::from_biguint(Sign::Plus, sk.d.clone()), &BigInt::from_biguint(Sign::Plus, phi.clone()));
    let (_,e) = ((exgcd.x + BigInt::from_biguint(Sign::Plus, phi.clone())) % BigInt::from_biguint(Sign::Plus, phi.clone())).into_parts();

    PublicKey{n:sk.p.clone()*sk.q.clone(),e}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gen_key() {
        let (pk,sk) = gen_key();
        assert_eq!(pk.n,sk.p.clone()*sk.q.clone());
        assert_eq!((pk.e*sk.d)%((sk.p-1u8)*(sk.q-1u8)),BigUint::one());
    }

    #[test]
    fn test_gen_pubkey() {
        let (pk, sk) = gen_key();
        let pk2 = gen_pubkey(&sk);
        assert_eq!(pk.e,pk2.e);
        assert_eq!(pk.n,pk2.n);
    }
}