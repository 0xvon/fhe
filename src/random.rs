use super::poly::Poly;
use rand::distributions::{Distribution, Uniform};
use rand::{CryptoRng, RngCore};
use rand_distr::Normal;

pub fn get_gaussian<T: RngCore + CryptoRng>(std_dev: f64, dimension: usize, rng: &mut T) -> Poly {
    let gaussian = Normal::new(0.0, std_dev).unwrap();
    let val = (0..dimension)
        .map(|_| gaussian.sample(rng).abs() as i64)
        .collect();
    Poly::new(val)
}

pub fn get_uniform<T: RngCore + CryptoRng>(bound: i64, dimension: usize, rng: &mut T) -> Poly {
    let between = Uniform::new(0, bound);

    let val = (0..dimension).map(|_| between.sample(rng)).collect();
    Poly::new(val)
}
