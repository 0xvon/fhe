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
    use crate::ciphertext::Ciphertext;
    use crate::poly::Poly;

    fn basic_mul_helper(msg_1: &Vec<i64>, msg_2: &Vec<i64>, t: i64, q: i64, std_dev: f64) {
        let n = msg_1.len();
        let a = msg_1.clone();
        let b = msg_2.clone();

        let ct_1 = Ciphertext {
            c_1: Poly::new(a.clone()),
            c_2: Poly::new(b.clone()),
            q,
            t,
        };
        let ct_2 = Ciphertext {
            c_1: Poly::new(a.clone()),
            c_2: Poly::new(b.clone()),
            q,
            t,
        };
        let delta_inv = t as f64 / q as f64;

        // run basic_mul
        let (c_1_prime, c_2_prime, c_3_prime) = ct_1.clone().basic_mul(ct_2.clone());

        let c_1_prime_raw = (ct_1.c_1.clone() * ct_2.c_1.clone()) * delta_inv;
        let c_2_prime_raw =
            (ct_1.c_1.clone() * ct_2.c_2.clone() + ct_1.c_2.clone() * ct_2.c_1.clone()) * delta_inv;
        let c_3_prime_raw = (ct_1.c_2.clone() * ct_2.c_2.clone()) * delta_inv;

        // check non-zero
        assert_ne!(c_1_prime.norm(), 0, "||c1'|| = 0");
        assert_ne!(c_2_prime.norm(), 0, "||c2'|| = 0");
        assert_ne!(c_3_prime.norm(), 0, "||c3'|| = 0");

        assert_eq!(c_1_prime, c_1_prime_raw % (q, n));
        assert_eq!(c_2_prime, c_2_prime_raw % (q, n));
        assert_eq!(c_3_prime, c_3_prime_raw % (q, n));
    }

    #[test]
    fn test_ciphertext_basic_mul() {
        for t in vec![32].iter() {
            basic_mul_helper(&vec![0, 6], &vec![7, 2], *t, 65536, 1.0);
            // basic_mul_helper(&vec![3, 2, 1, 0], &vec![1, 2, 3, 4], *t, 65536, 1.0);
            basic_mul_helper(
                &vec![33, 25, 1, 50, 33, 21, 17, 32],
                &vec![27, 99, 22, 1, 5, 41, 22, 3],
                *t,
                65536,
                3.2,
            );
        }
    }
}
