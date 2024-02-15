use super::keygen::{RelinearizationKeyV1, RelinearizationKeyV2, SecretKey};
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

    pub fn basic_mul(&self, other: Ciphertext) -> (Poly, Poly, Poly) {
        let degree = self.c_1.degree();
        assert_eq!(degree, self.c_2.degree());
        assert_eq!(degree, other.c_1.degree());
        assert_eq!(degree, other.c_2.degree());

        // c1_1 * c2_1
        let out_1_raw = self.c_1.clone() * other.c_1.clone();

        // inner product, c1_1 * c2_2 + c1_2 * c2_1
        let out_2_raw = self.c_1.clone() * other.c_2.clone() + self.c_2.clone() * other.c_1.clone();

        // c1_2 * c2_2
        let out_3_raw = self.c_2.clone() * other.c_2.clone();

        let delta_inv = self.t as f64 / self.q as f64;
        let out_1 = (out_1_raw * delta_inv) % (self.q, degree);
        let out_2 = (out_2_raw * delta_inv) % (self.q, degree);
        let out_3 = (out_3_raw * delta_inv) % (self.q, degree);

        (out_1, out_2, out_3)
    }

    // TODO: impl relinealize
    pub fn relinearize_v1(
        &self,
        c_1: Poly,
        c_2: Poly,
        c_3: Poly,
        rlk: &RelinearizationKeyV1,
    ) -> Ciphertext {
        let degree = c_1.degree();
        let c_3_decom = c_3.decompose(rlk.l, rlk.base);

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
        c_1: Poly,
        c_2: Poly,
        c_3: Poly,
        rlk: &RelinearizationKeyV2,
    ) -> Ciphertext {
        let degree = c_1.degree();
        let p = rlk.p as f64;

        let c_2_1 = (c_3.clone() * rlk.rlk_0.clone() / p) % (self.q, degree);
        let c_2_2 = (c_3.clone() * rlk.rlk_1.clone() / p) % (self.q, degree);
        Ciphertext {
            c_1: (c_1 + c_2_1) % (self.q, degree),
            c_2: (c_2 + c_2_2) % (self.q, degree),
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
impl Mul<(Ciphertext, &RelinearizationKeyV1)> for Ciphertext {
    type Output = Self;
    fn mul(self, rhs: (Ciphertext, &RelinearizationKeyV1)) -> Self::Output {
        let (rhs_ct, rlk) = rhs;
        let (c_1, c_2, c_3) = self.basic_mul(rhs_ct);
        self.relinearize_v1(c_1, c_2, c_3, rlk)
    }
}

impl Mul<(Ciphertext, &RelinearizationKeyV2)> for Ciphertext {
    type Output = Self;
    fn mul(self, rhs: (Ciphertext, &RelinearizationKeyV2)) -> Self::Output {
        let (rhs_ct, rlk) = rhs;
        let (c_1, c_2, c_3) = self.basic_mul(rhs_ct);
        self.relinearize_v2(c_1, c_2, c_3, rlk)
    }
}
