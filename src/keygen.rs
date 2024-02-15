use super::poly::Poly;
use super::random;
use rand::{CryptoRng, RngCore};

// Parameter:
// R_2: key distribution used to sample polynomials with integer coefficients in {-1, 0, 1}
// chi: error distribution defined as a discrete Gaussian distribution
// R_q: uniform random distribution over R_q

#[derive(Clone, Debug)]
pub struct SecretKey {
    pub(crate) sk: Poly, // <- R_2
}

#[derive(Clone)]
pub struct PublicKey {
    pub(crate) pk_1: Poly, // [-1(a*sk+e)]_q
    pub(crate) pk_2: Poly, // a <- R_q
    pub(crate) q: i64,
}

#[derive(Clone, Debug)]
pub struct RelinearizationKeyV1 {
    pub(crate) val: Vec<(Poly, Poly)>, // (-[(a_i*sk+e_i) + T^i * sk^2]_q, a_i) for all i in (0..l)
    pub(crate) base: i64,              // T: decomposition base
    pub(crate) l: usize,               // floor(log_t(q)): level to decompose
}

#[derive(Clone, Debug)]
pub struct RelinearizationKeyV2 {
    pub(crate) rlk_0: Poly, // ([-(a*sk + e) + p*sk^2]_{pq})
    pub(crate) rlk_1: Poly, // a
    pub(crate) p: i64,      // the amount to scale the modulus, during mudulus switching
}

impl SecretKey {
    // degree: the polynomial degree of the secret key
    pub fn generate_sk<T: RngCore + CryptoRng>(degree: usize, rng: &mut T) -> Self {
        // random from R_2
        SecretKey {
            sk: random::get_uniform(2, degree, rng),
        }
    }

    // q = 65536
    // std_dev = 3.2
    pub fn generate_pk<T: RngCore + CryptoRng>(
        &self,
        q: i64,
        std_dev: f64,
        rng: &mut T,
    ) -> PublicKey {
        let sk = self.sk.clone();
        let degree = sk.degree();

        let a = random::get_uniform(q, degree, rng);
        let e = random::get_gaussian(std_dev, degree, rng);
        let pk_1 = (-(a.clone() * sk.clone() + e)) % (q, degree);
        let pk_2 = a.clone();

        PublicKey { pk_1, pk_2, q }
    }

    // base: T
    pub fn generate_relin_key_v1<T: RngCore + CryptoRng>(
        &self,
        q: i64,
        std_dev: f64,
        rng: &mut T,
        base: i64,
    ) -> RelinearizationKeyV1 {
        let degree = self.sk.degree();
        let sk = self.sk.clone();
        // l = floor(log_T(q))
        let l = (q as f64).log(base as f64).floor() as usize;
        // (-[(a_i*s+e_i) + T^i * s^2]_q, a_i) for all i in (0..l)
        let val = (0..l)
            .map(|i| {
                let a_i = random::get_uniform(q, degree, rng);
                let e_i = random::get_gaussian(std_dev, degree, rng);
                let base_i = base.pow(i as u32);
                let rlk_i_raw =
                    -(a_i.clone() * sk.clone() + e_i) + sk.clone() * sk.clone() * base_i;
                let rlk_i = rlk_i_raw % (q, degree);
                (rlk_i, a_i)
            })
            .collect();
        RelinearizationKeyV1 { val, base, l }
    }

    // q: cipher-text modulus
    // std_dev: standard deviation for error generation
    // p: scaling modulus
    pub fn generate_relin_key_v2<T: RngCore + CryptoRng>(
        &self,
        q: i64,
        std_dev: f64,
        rng: &mut T,
        p: i64,
    ) -> RelinearizationKeyV2 {
        let degree = self.sk.degree();
        let sk = self.sk.clone();

        let a = random::get_uniform(p * q, degree, rng);
        let e = random::get_gaussian(std_dev, degree, rng);
        // [-(a*sk + e) + p * sk^2]_{pq}
        let rlk_0 = (-(a.clone() * sk.clone() + e) + sk.clone() * sk.clone() * p) % (p * q, degree);
        RelinearizationKeyV2 { rlk_0, rlk_1: a, p }
    }
}
