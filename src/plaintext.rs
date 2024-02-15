use crate::ciphertext::Ciphertext;

use super::keygen::PublicKey;
use super::poly::Poly;
use super::random;
use rand::{CryptoRng, RngCore};

#[derive(Debug, PartialEq)]
pub struct Plaintext {
    m: Poly,
    t: i64,
}

impl Plaintext {
    // Plaintext Encoding
    // m: bit vector of message
    // M: polynomial (bit to each coeff)
    // let m = 10010
    // M = 1x^4 + 0x^3 + 0x^2 + 1x + 0
    pub fn new(m: Vec<i64>, t: i64) -> Plaintext {
        Plaintext::new_from_poly(Poly::new(m), t)
    }

    pub(crate) fn new_from_poly(poly: Poly, t: i64) -> Plaintext {
        assert!(t > 1);
        Plaintext { m: poly, t }
    }

    pub fn generate_random_plaintext<T: RngCore + CryptoRng>(
        degree: usize,
        t: i64,
        rng: &mut T,
    ) -> Plaintext {
        assert!(t > 1);
        Plaintext {
            m: random::get_uniform(t, degree, rng),
            t,
        }
    }

    pub fn m(&self) -> Poly {
        self.m.clone()
    }

    // u <- R_2
    // e_1 <- chi
    // e_2 <- chi
    // C1 = [pk_1 * u + e_1 + ΔM]_q
    // C2 = [pk_2 * u + e_2]_q
    pub fn encrypt<T: RngCore + CryptoRng>(
        &self,
        pk: &PublicKey,
        std_dev: f64,
        rng: &mut T,
    ) -> Ciphertext {
        let q = pk.q;
        let degree = self.m.degree();
        let m = self.m.clone();
        // Δ = q/t
        let delta = (q as f64 / self.t as f64).floor() as i64;

        // sample randoms u, e_1, e_2
        let u = random::get_uniform(2, degree, rng);
        let e_1 = random::get_gaussian(std_dev, degree, rng);
        let e_2 = random::get_gaussian(std_dev, degree, rng);

        let c_1 = (pk.pk_1.clone() * u.clone() + e_1 + m * delta) % (q, degree);
        let c_2 = (pk.pk_2.clone() * u + e_2) % (q, degree);

        Ciphertext {
            c_1,
            c_2,
            q,
            t: self.t,
        }
    }
}
