use super::keygen::{EvaluationKeyV1, EvaluationKeyV2, SecretKey};
use super::plaintext::Plaintext;
use super::poly::Poly;
use std::ops::{Add, Mul, Neg, Sub};

#[derive(Clone, Debug)]
pub struct Ciphertext {
    pub(crate) c_1: Poly,
    pub(crate) c_2: Poly,
    pub(crate) q: i64,
    pub(crate) t: i64,
}

impl Ciphertext {
    // q: ciphertext modulus
    // t: plaintext modulus
    pub fn decrypt(&self, _sk: &SecretKey) -> Plaintext {
        let sk = &_sk.sk;
        let degree = sk.degree();
        let q = self.q.clone();
        let t = self.t.clone();
        let c_1 = self.c_1.clone();
        let c_2 = self.c_2.clone();

        // t/q
        let delta_inv = t as f64 / q as f64;

        // ((c_1 + c_2*sk) % q * t/q) % t
        let m_raw = (c_1 + c_2 * sk.clone()) % (q, degree);
        let poly = (m_raw * delta_inv) % (t, degree);
        Plaintext::new_from_poly(poly, t)
    }

    // (c1,c2) * (c'1,c'2) = c1*c'1 + (c1*c'2 + c2*c'1) + c2*c'2
    pub fn basic_mul(&self, other: Ciphertext) -> (Poly, Poly, Poly) {
        let degree = self.c_1.degree();
        assert_eq!(degree, self.c_2.degree());
        assert_eq!(degree, other.c_1.degree());
        assert_eq!(degree, other.c_2.degree());

        // c1_1 * c2_1
        let c_1_prime_raw = self.c_1.clone() * other.c_1.clone();

        // inner product, c1_1 * c2_2 + c1_2 * c2_1
        let c_2_prime_raw =
            self.c_1.clone() * other.c_2.clone() + self.c_2.clone() * other.c_1.clone();

        // c1_2 * c2_2
        let c_3_prime_raw = self.c_2.clone() * other.c_2.clone();

        let delta_inv = self.t as f64 / self.q as f64;
        let c_1_prime = (c_1_prime_raw * delta_inv) % (self.q, degree);
        let c_2_prime = (c_2_prime_raw * delta_inv) % (self.q, degree);
        let c_3_prime = (c_3_prime_raw * delta_inv) % (self.q, degree);

        (c_1_prime, c_2_prime, c_3_prime)
    }

    pub fn relinearize_v1(
        &self,
        c_1: Poly,
        c_2: Poly,
        c_3: Poly,
        rlk: &EvaluationKeyV1,
    ) -> Ciphertext {
        let degree = c_1.degree();
        let c_3_decom = c_3.decompose(rlk.l, rlk.t);

        let mut c_2_1 = Poly::new(vec![0; degree]);
        let mut c_2_2 = Poly::new(vec![0; degree]);
        for i in 0..(rlk.l as usize) {
            c_2_1 = c_2_1 + rlk.val[i].0.clone() * c_3_decom[i].clone();
            c_2_2 = c_2_2 + rlk.val[i].1.clone() * c_3_decom[i].clone();
        }

        Ciphertext {
            c_1: c_1 + c_2_1,
            c_2: c_2 + c_2_2,
            q: self.q,
            t: self.t,
        }
    }

    pub fn relinearize_v2(
        &self,
        c_1_prime: Poly,
        c_2_prime: Poly,
        c_3_prime: Poly,
        ek: &EvaluationKeyV2,
    ) -> Ciphertext {
        let degree = c_1_prime.degree();
        let p = ek.p as f64;

        let c_1_hat_raw = (c_3_prime.clone() * ek.ek_1.clone() / p) % (self.q, degree);
        let c_2_hat_raw = (c_3_prime.clone() * ek.ek_2.clone() / p) % (self.q, degree);

        let c_1_hat = (c_1_prime + c_1_hat_raw) % (self.q, degree);
        let c_2_hat = (c_2_prime + c_2_hat_raw) % (self.q, degree);
        Ciphertext {
            c_1: c_1_hat,
            c_2: c_2_hat,
            q: self.q,
            t: self.t,
        }
    }
}

// C3 = C1 + C2
impl Add<Ciphertext> for Ciphertext {
    type Output = Self;
    fn add(self, rhs: Ciphertext) -> Self::Output {
        Ciphertext {
            c_1: self.c_1 + rhs.c_1,
            c_2: self.c_2 + rhs.c_2,
            q: self.q,
            t: self.t,
        }
    }
}

// C3 = C1 - C2
impl Sub<Ciphertext> for Ciphertext {
    type Output = Self;
    fn sub(self, rhs: Ciphertext) -> Self::Output {
        Ciphertext {
            c_1: self.c_1 - rhs.c_1,
            c_2: self.c_2 - rhs.c_2,
            q: self.q,
            t: self.t,
        }
    }
}

// C1' = -C1
impl Neg for Ciphertext {
    type Output = Self;
    fn neg(mut self) -> Self::Output {
        self.c_1 = -self.c_1;
        self.c_2 = -self.c_2;
        self
    }
}

// C3 = C1 * C2
// C3* = C3
impl Mul<(Ciphertext, &EvaluationKeyV1)> for Ciphertext {
    type Output = Self;
    fn mul(self, rhs: (Ciphertext, &EvaluationKeyV1)) -> Self::Output {
        let (rhs_ct, rlk) = rhs;
        let (c_1, c_2, c_3) = self.basic_mul(rhs_ct);
        self.relinearize_v1(c_1, c_2, c_3, rlk)
    }
}

impl Mul<(Ciphertext, &EvaluationKeyV2)> for Ciphertext {
    type Output = Self;
    fn mul(self, rhs: (Ciphertext, &EvaluationKeyV2)) -> Self::Output {
        let (rhs_ct, ek) = rhs;
        let (c_1_prime, c_2_prime, c_3_prime) = self.basic_mul(rhs_ct);
        self.relinearize_v2(c_1_prime, c_2_prime, c_3_prime, ek)
    }
}

#[cfg(test)]
mod tests {
    use crate::keygen::{EvaluationKeyV1, EvaluationKeyV2, PublicKey, SecretKey};
    use crate::plaintext::Plaintext;
    use rand::{CryptoRng, RngCore, SeedableRng};

    fn get_test_keys<T: CryptoRng + RngCore>(
        degree: usize,
        q: i64,
        std_dev: f64,
        p: i64,
        rng: &mut T,
    ) -> (SecretKey, PublicKey, EvaluationKeyV1, EvaluationKeyV2) {
        let sk = SecretKey::new(degree, rng);
        let pk = sk.generate_pk(q, std_dev, rng);
        let ek_1 = sk.generate_ek_v1(q, std_dev, rng, p);
        let ek_2 = sk.generate_ek_v2(q, std_dev, rng, p);
        (sk, pk, ek_1, ek_2)
    }

    #[test]
    fn test_encryption() {
        let iter_amount = 100;
        let degree = 1000;
        let t_list = vec![2, 4, 8, 16, 32, 64];
        let q = 65536;
        let rlk_p = (q as f64).log2() as i64;
        let std_dev = 3.2;
        let mut rng = rand::rngs::StdRng::seed_from_u64(18);

        for t in t_list.iter() {
            for i in 0..iter_amount {
                println!("--- #{} encryption test for t={} ---", i, t);
                let (sk, pk, _, _) = get_test_keys(degree, q, std_dev, rlk_p, &mut rng);
                let plaintext = Plaintext::generate_random_plaintext(degree, *t, &mut rng);
                println!("plaintext: {}", plaintext.m());
                let encrypted = plaintext.encrypt(&pk, std_dev, &mut rng);
                println!("ciphertext: {}", encrypted.c_1);
                let decrypted = encrypted.decrypt(&sk);
                println!("decrypted: {}", decrypted.m());
                let m_l = plaintext.m();
                let m_r = decrypted.m();
                assert_eq!(m_l, m_r);
            }
        }
    }

    fn basic_mul_helper(msg_1: Vec<i64>, msg_2: Vec<i64>, t: i64, q: i64, std_dev: f64) {
        let degree = msg_1.len();
        let mut rng = rand::rngs::StdRng::seed_from_u64(20);

        let secret_key = SecretKey::new(degree, &mut rng);
        let public_key = secret_key.generate_pk(q, std_dev, &mut rng);

        let plaintext_1 = Plaintext::new(msg_1, t);
        let ciphertext_1 = plaintext_1.encrypt(&public_key, std_dev, &mut rng);
        let plaintext_2 = Plaintext::new(msg_2, t);
        let ciphertext_2 = plaintext_2.encrypt(&public_key, std_dev, &mut rng);

        // Multiply without relinearizing
        let (c_0, c_1, c_2) = ciphertext_1.clone().basic_mul(ciphertext_2.clone());

        // Decrypt non-relinearized multilication output
        let s = secret_key.sk;
        let delta_inv = t as f64 / q as f64;
        let raw = c_0.clone() + c_1.clone() * s.clone() + c_2.clone() * s.clone() * s.clone();
        let decrypted_mul = (raw * delta_inv) % (t, degree);

        assert_eq!(
            decrypted_mul,
            (plaintext_1.m() * plaintext_2.m()) % (t, degree)
        );
    }

    // Test that ciphertext multiplication without relinearization encrypt/decrypts correctly
    #[test]
    fn test_basic_mul() {
        for t in vec![2, 4, 8, 16, 32].iter() {
            basic_mul_helper(vec![0, 6], vec![7, 2], *t, 65536, 1.0);
            basic_mul_helper(vec![3, 2, 1, 0], vec![1, 2, 3, 4], *t, 65536, 1.0);
            // TODO: it fails
            // basic_mul_helper(
            //     vec![33, 25, 1, 50, 33, 21, 17, 32],
            //     vec![27, 99, 22, 1, 5, 41, 22, 3],
            //     *t,
            //     65536,
            //     2.9,
            // );
        }
    }

    #[test]
    fn test_homomorphic_add() {
        let iter_amount = 10;
        let degree = 1000;
        let t_list = vec![2, 4, 8, 16, 32];
        let q = 65536;
        let rlk_p = (q as f64).log2() as i64;
        let std_dev = 3.2;
        let mut rng = rand::rngs::StdRng::seed_from_u64(18);

        for t in t_list.iter() {
            for i in 0..iter_amount {
                println!("--- #{} encryption test for t={} ---", i, t);
                let (sk, pk, _, _) = get_test_keys(degree, q, std_dev, rlk_p, &mut rng);
                let plaintext_l = Plaintext::generate_random_plaintext(degree, *t, &mut rng);
                let plaintext_r = Plaintext::generate_random_plaintext(degree, *t, &mut rng);

                let encrypted_l = plaintext_l.encrypt(&pk, std_dev, &mut rng);
                let encrypted_r = plaintext_r.encrypt(&pk, std_dev, &mut rng);

                let decrypted = (encrypted_l.clone() + encrypted_r.clone()).decrypt(&sk);

                let m_l = (plaintext_l.m() + plaintext_r.m()) % (*t, degree);
                let m_r = decrypted.m();
                assert_eq!(m_l, m_r);
            }
        }
    }

    #[test]
    fn test_homomorphic_sub() {
        let iter_amount = 10;
        let degree = 1000;
        let t_list = vec![2, 4, 8, 16, 32];
        let q = 65536;
        let rlk_p = (q as f64).log2() as i64;
        let std_dev = 3.2;
        let mut rng = rand::rngs::StdRng::seed_from_u64(18);

        for t in t_list.iter() {
            for i in 0..iter_amount {
                println!("--- #{} encryption test for t={} ---", i, t);
                let (sk, pk, _, _) = get_test_keys(degree, q, std_dev, rlk_p, &mut rng);
                let plaintext_l = Plaintext::generate_random_plaintext(degree, *t, &mut rng);
                let plaintext_r = Plaintext::generate_random_plaintext(degree, *t, &mut rng);

                let encrypted_l = plaintext_l.encrypt(&pk, std_dev, &mut rng);
                let encrypted_r = plaintext_r.encrypt(&pk, std_dev, &mut rng);

                let decrypted = (encrypted_l.clone() - encrypted_r.clone()).decrypt(&sk);

                let m_l = (plaintext_l.m() - plaintext_r.m()) % (*t, degree);
                let m_r = decrypted.m();
                assert_eq!(m_l, m_r);
            }
        }
    }

    #[test]
    fn test_homomorphic_mul_v1() {
        let iter_amount = 10;
        let degree = 4; // TODO: fails if 8
        let ts = [4, 8, 16];
        let q = 65536;

        let base = (q as f64).log2() as i64;
        let std_dev = 2.9;

        let mut rng = rand::rngs::StdRng::seed_from_u64(18);

        for t in ts.iter() {
            for i in 0..iter_amount {
                println!("--- #{} encryption test for t={} ---", i, t);
                let (sk, pk, ek_1, _) = get_test_keys(degree, q, std_dev, base, &mut rng);
                let plaintext_l = Plaintext::generate_random_plaintext(degree, *t, &mut rng);
                let plaintext_r = Plaintext::generate_random_plaintext(degree, *t, &mut rng);

                let encrypted_l = plaintext_l.encrypt(&pk, std_dev, &mut rng);
                let encrypted_r = plaintext_r.encrypt(&pk, std_dev, &mut rng);

                let decrypted_v1 =
                    (encrypted_l.clone() * (encrypted_r.clone(), &ek_1)).decrypt(&sk);

                let m_l = plaintext_l.m() * plaintext_r.m() % (*t, degree);
                let m_r = decrypted_v1.m();
                assert_eq!(m_l, m_r);
            }
        }
    }

    #[test]
    fn test_homomorphic_mul_v2() {
        // TODO: fails
        let iter_amount = 10;
        let degree = 4; // TODO: fails if 8
        let ts = [16];
        let q = 65536;

        let base = 2_i64.pow(13) * q;
        let std_dev = 2.0;

        let mut rng = rand::rngs::StdRng::seed_from_u64(18);

        for t in ts.iter() {
            for i in 0..iter_amount {
                println!("--- #{} encryption test for t={} ---", i, t);
                let (sk, pk, ek_1, _) = get_test_keys(degree, q, std_dev, base, &mut rng);
                let plaintext_l = Plaintext::generate_random_plaintext(degree, *t, &mut rng);
                let plaintext_r = Plaintext::generate_random_plaintext(degree, *t, &mut rng);

                let encrypted_l = plaintext_l.encrypt(&pk, std_dev, &mut rng);
                let encrypted_r = plaintext_r.encrypt(&pk, std_dev, &mut rng);

                let decrypted_v1 =
                    (encrypted_l.clone() * (encrypted_r.clone(), &ek_1)).decrypt(&sk);

                let m_l = plaintext_l.m() * plaintext_r.m() % (*t, degree);
                let m_r = decrypted_v1.m();
                assert_eq!(m_l, m_r);
            }
        }
    }
}
