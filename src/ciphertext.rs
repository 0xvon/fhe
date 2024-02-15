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
