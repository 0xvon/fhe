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
        let ek_2 = sk.generate_ek_v1(q, std_dev, rng, p);
        let rlk_2 = sk.generate_ek_v2(q, std_dev, rng, p);
        (sk, pk, ek_2, rlk_2)
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
    fn test_homomorphic_mul() {
        let iter_amount = 10;
        let degree = 8;
        let t_list = vec![4, 8, 16];
        let q = 65536;
        let rlk_p = (q as f64).log2() as i64;
        let std_dev = 2.9;
        let mut rng = rand::rngs::StdRng::seed_from_u64(18);

        for t in t_list.iter() {
            for i in 0..iter_amount {
                println!("--- #{} encryption test for t={} ---", i, t);
                let (sk, pk, ek_2, rlk_2) = get_test_keys(degree, q, std_dev, rlk_p, &mut rng);
                let plaintext_l = Plaintext::generate_random_plaintext(degree, *t, &mut rng);
                let plaintext_r = Plaintext::generate_random_plaintext(degree, *t, &mut rng);

                let encrypted_l = plaintext_l.encrypt(&pk, std_dev, &mut rng);
                let encrypted_r = plaintext_r.encrypt(&pk, std_dev, &mut rng);

                let decrypted_v1 =
                    (encrypted_l.clone() * (encrypted_r.clone(), &ek_2)).decrypt(&sk);
                let decrypted_v2 =
                    (encrypted_l.clone() * (encrypted_r.clone(), &rlk_2)).decrypt(&sk);

                let m_l = plaintext_l.m() * plaintext_r.m() % (*t, degree);
                let m_r1 = decrypted_v1.m();
                let m_r2 = decrypted_v2.m();
                assert_eq!(m_l, m_r1);
                assert_eq!(m_l, m_r2);
            }
        }
    }
}
