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
        let out_val = self.0.into_iter().map(|self_i| self_i * other).collect();
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
            .map(|self_i| (self_i as f64 * other).round() as i64)
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
        let t = modulus.0;
        // N
        let n = modulus.1;
        let mut out_val = vec![0; n];

        // X^i = X^{i+j*2N} mod (X^N+1) for all j
        for (i, coeff) in self.0.iter().enumerate() {
            let reduced_i = i % (2 * n);

            // if n % 2n >= n
            if reduced_i >= n {
                // coeff should ge negated and added to the N % 2N
                out_val[reduced_i % n] -= coeff;
            } else {
                // coeff should ge added to the N % 2N
                out_val[reduced_i] += coeff;
            }
        }

        // coeff % t
        for coeff in out_val.iter_mut() {
            *coeff = Poly::mod_coeff(*coeff, t)
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

    pub fn norm(&self) -> i64 {
        self.0.iter().sum()
    }

    // modulo operation for coefficient(constant)
    // add by q to change negative value to positive
    fn mod_coeff(coeff: i64, q: i64) -> i64 {
        (coeff % q + q) % q
    }

    // decompose a poly to l levels, with each level base T, s.t.
    // $poly = sum_{i=0}^l poly^i T^i$
    // with
    // $poly^i ∈ R_T$
    pub fn decompose(self, l: usize, t: i64) -> Vec<Poly> {
        let mut mut_poly = self.clone();

        // for all 0≤i<l, starting from l to 0
        let out_polys: Vec<Poly> = (0..l)
            .rev()
            .map(|i| {
                // T^i: multiplier for that level i
                let t_i = t.pow(i as u32);

                // polyのj項ごとに計算
                let dec_val_i = mut_poly
                    .0
                    .iter_mut()
                    .map(|val_j| {
                        // calculate how many times T^i divides the coefficient
                        // to get decomposition
                        // a_j/T^i
                        let fl_div = *val_j as f64 / t_i as f64;

                        // if a_j/T^i > 0.0 then
                        let int_div = if fl_div > 0.0 {
                            fl_div.floor()
                        } else {
                            fl_div.ceil()
                        } as i64;

                        // subtract T^i * the decomposed value
                        *val_j = *val_j - t_i * int_div;

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
    fn test_poly_add() {
        let a = a_poly();
        let b = b_poly();
        let sum = a + b;
        assert_eq!(sum.0, vec![-8, -1, 0, 4, -1, 5, -2, 6, 8, -6]);

        let c = Poly(vec![3, -1, 6, -3]);
        let sum_uneven = c + sum;
        assert_eq!(sum_uneven.0, vec![-5, -2, 6, 1, -1, 5, -2, 6, 8, -6]);
    }

    #[test]
    fn test_poly_mul() {
        let a = Poly(vec![4, 5, 2]);
        let b = Poly(vec![7, 9, 1]);
        let mul = a * b;
        assert_eq!(mul.0, vec![28, 71, 63, 23, 2]);
    }

    #[test]
    fn test_poly_modulo_x() {
        // a(x) = x^2+1 , b(x) = 2x^2 - 1
        let a = Poly(vec![1, 0, 1]);
        let b = Poly(vec![-1, 0, 2]);
        // a(x) * b(x) = 2x^4 + x^2 - 1
        let ab = a * b;
        assert_eq!(ab.0, vec![-1, 0, 1, 0, 2]);

        let ab_1 = ab + Poly(vec![1]); // plus by reminder

        // f(x) = g(x)(2x^2 - 1) + 1
        let mod_ab_1 = ab_1.clone() % (2, 2);
        assert_eq!(mod_ab_1.0, [1, 0]);
    }

    #[test]
    fn test_poly_modulo() {
        let a = a_poly();
        let b = b_poly();
        let mul = a * b;
        assert_eq!(
            mul.0,
            vec![7, 7, 0, -10, -2, 2, -7, -10, -4, 4, 6, 14, -9, -12, 16, 2, -19, -4, 5]
        );
        let mod_degree_2 = mul.clone() % (16, 2);
        assert_eq!(mod_degree_2.0, vec![1, 1]);
        let mod_degree_4 = mul.clone() % (16, 4);
        assert_eq!(mod_degree_4.0, vec![11, 1, 2, 12]);
        let mod_degree_8 = mul.clone() % (16, 8);
        assert_eq!(mod_degree_8.0, vec![8, 15, 15, 8, 7, 14, 9, 4]);
        let mod_degree_16 = mul.clone() % (16, 16);
        assert_eq!(
            mod_degree_16.0,
            vec![10, 11, 11, 6, 14, 2, 9, 6, 12, 4, 6, 14, 7, 4, 0, 2]
        );
    }

    #[test]
    fn test_poly_coeff_modulo() {
        let a = a_poly();
        let modulo = a % (4, 10);
        assert_eq!(modulo.0, vec![1, 0, 0, 3, 3, 2, 1, 1, 1, 3]);
    }

    #[test]
    fn test_poly_decomposition() {
        let a = a_poly();
        let dec = a.clone().decompose(4, 2);

        assert_eq!(dec[0].0, vec![-1, 0, 0, 1, -1, 0, -1, 1, 1, -1]);
        assert_eq!(dec[1].0, vec![-1, 0, 0, 1, 0, 1, -1, 0, 0, 0]);
        assert_eq!(dec[2].0, vec![-1, 0, 0, 0, 0, 1, 0, 1, 0, -1]);
        assert_eq!(dec[3].0, vec![0, 0, 0, 0, 0, 0, 0, 0, 1, 0]);

        let recomposed =
            dec[0].clone() + dec[1].clone() * 2 + dec[2].clone() * 4 + dec[3].clone() * 8;
        assert_eq!(recomposed, a);
    }
}
