use std::ops::{Add, Div, Mul, Neg, Rem, Sub};
use std::{cmp, fmt};

#[derive(Clone, Debug, PartialEq)]
pub struct Poly(Vec<i64>);

impl Add<Poly> for Poly {
    type Output = Poly;
    fn add(self, other: Poly) -> Self::Output {
        let max_degree = cmp::max(self.degree(), other.degree());

        let out_val = (0..max_degree)
            .map(|i| {
                let self_i = if i < self.degree() { self.0[i] } else { 0 };
                let other_i = if i < other.degree() { other.0[i] } else { 0 };
                self_i + other_i
            })
            .collect();

        Poly(out_val)
    }
}

impl Sub<Poly> for Poly {
    type Output = Poly;
    fn sub(self, other: Poly) -> Self::Output {
        let max_degree = cmp::max(self.degree(), other.degree());

        let out_val = (0..max_degree)
            .map(|i| {
                let self_i = if i < self.degree() { self.0[i] } else { 0 };
                let other_i = if i < other.degree() { other.0[i] } else { 0 };
                self_i - other_i
            })
            .collect();

        Poly(out_val)
    }
}

impl Neg for Poly {
    type Output = Self;
    fn neg(mut self) -> Self::Output {
        for v in self.0.iter_mut() {
            *v = -*v;
        }
        self
    }
}

// mul by const integer
impl Mul<i64> for Poly {
    type Output = Poly;
    fn mul(self, other: i64) -> Self::Output {
        let out_val = self.0.into_iter().map(|i| i * other).collect();
        Poly(out_val)
    }
}

// mul by const float
impl Mul<f64> for Poly {
    type Output = Poly;
    fn mul(self, other: f64) -> Self::Output {
        let out_val = self
            .0
            .into_iter()
            .map(|i| (i as f64 * other).round() as i64)
            .collect();
        Poly(out_val)
    }
}

impl Div<f64> for Poly {
    type Output = Poly;
    fn div(self, other: f64) -> Self::Output {
        let other_inv = 1.0 / other;
        self * other_inv
    }
}

// mul by polynomial
impl Mul<Poly> for Poly {
    type Output = Poly;
    fn mul(self, other: Poly) -> Self::Output {
        let mut out_val = vec![0; self.0.len() + other.0.len() - 1];
        for (i, self_i) in self.0.iter().enumerate() {
            for (j, other_j) in other.0.iter().enumerate() {
                let target_degree = i + j;
                out_val[target_degree] += self_i * other_j;
            }
        }
        Poly(out_val)
    }
}

impl Rem<(i64, usize)> for Poly {
    type Output = Poly;
    fn rem(self, modulus: (i64, usize)) -> Self::Output {
        // take mod (X^N + 1) for poly, then mod t for each coefficient
        // t
        let coeff_mod = modulus.0;
        // N
        let degree = modulus.1;
        let mut out_val = vec![0; degree];

        // X^i = X^{i+j*2N} mod (X^N+1) for all j
        for (i, coeff) in self.0.iter().enumerate() {
            let reduced_i = i % (2 * degree);

            // TODO: ">"???
            if reduced_i >= degree {
                // if N % 2N > N, coeff should ge negated and added to the N % 2N
                out_val[reduced_i % degree] -= coeff;
            } else {
                // if N % 2N ≤ N, coeff should ge added to the N % 2N
                out_val[reduced_i] += coeff;
            }
        }

        // coeff % t
        for coeff in out_val.iter_mut() {
            *coeff = Poly::mod_coeff(*coeff, coeff_mod)
        }
        Poly(out_val)
    }
}

impl fmt::Display for Poly {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            write!(f, "0")
        } else {
            for (power, coeff) in self.0.iter().enumerate() {
                if *coeff != 0 {
                    match power {
                        0 => write!(f, "{}", coeff)?,
                        1 => write!(f, " + {} * x", coeff)?,
                        _ => write!(f, " + {} * X^{}", coeff, power)?,
                    }
                }
            }
            Ok(())
        }
    }
}

impl Poly {
    pub fn new(val: Vec<i64>) -> Poly {
        Poly(val)
    }

    pub fn degree(&self) -> usize {
        self.0.len()
    }

    pub fn val(&self) -> Vec<i64> {
        self.0.clone()
    }

    // reduce a coefficient into the [0,q) bounds
    fn mod_coeff(coeff: i64, q: i64) -> i64 {
        (coeff % q + q) % q
    }

    // decompose a poly to l levels, with each level base T, s.t.
    // $poly = sum_{i=0}^l poly^i T^i$
    // with
    // $poly^i ∈ R_T$
    pub fn decompose(self, l: usize, base: i64) -> Vec<Poly> {
        let mut mut_poly = self.clone();

        // for all 0≤i<l, starting from l to 0
        let out_polys: Vec<Poly> = (0..l)
            .rev()
            .map(|i| {
                // T^i: multiplier for that level i
                let base_i = base.pow(i as u32);

                let dec_val_i = mut_poly
                    .0
                    .iter_mut()
                    .map(|val_j| {
                        // calculate how many times T^i divides the coefficient
                        // to get decomposition
                        let fl_div = *val_j as f64 / base_i as f64;
                        let int_div = if fl_div > 0.0 {
                            fl_div.floor()
                        } else {
                            fl_div.ceil()
                        } as i64;

                        // subtract T^i * the decomposed value
                        *val_j = *val_j - base_i * int_div;

                        // return decomposed value for level i
                        int_div
                    })
                    .collect();
                Poly(dec_val_i)
            })
            .collect();

        out_polys.into_iter().rev().collect()
    }
}

#[cfg(test)]
mod tests {
    use crate::poly::Poly;

    fn a_poly() -> Poly {
        Poly(vec![-7, 0, 0, 3, -1, 6, -3, 5, 9, -5])
    }
    fn b_poly() -> Poly {
        Poly(vec![-1, -1, 0, 1, 0, -1, 1, 1, -1, -1])
    }

    #[test]
    fn test_add() {
        let a = a_poly();
        let b = b_poly();
        let sum = a + b;
        assert_eq!(sum.0, vec![-8, -1, 0, 4, -1, 5, -2, 6, 8, -6]);

        let c = Poly(vec![3, -1, 6, -3]);
        let sum_uneven = c + sum;
        assert_eq!(sum_uneven.0, vec![-5, -2, 6, 1, -1, 5, -2, 6, 8, -6]);
    }
}
