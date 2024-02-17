#[cfg(test)]
mod tests {
    use crate::keygen::SecretKey;
    use crate::plaintext::Plaintext;
    use rand::SeedableRng;

    #[test]
    fn end_to_end_test_v1() {
        for _ in 0..1000 {
            let q = 65536;
            let t = 16;
            let std_dev = 3.2;
            let degree = 4;
            let rlk_p = (q as f64).log2() as i64;
            let mut rng = rand::rngs::StdRng::seed_from_u64(23);

            let secret_key = SecretKey::new(degree, &mut rng);
            let public_key = secret_key.generate_pk(q, std_dev, &mut rng);
            let ek_1 = secret_key.generate_ek_v1(q, std_dev, &mut rng, rlk_p);

            let pt_1 = Plaintext::generate_random_plaintext(degree, t, &mut rng);
            let pt_2 = Plaintext::generate_random_plaintext(degree, t, &mut rng);
            let pt_3 = Plaintext::generate_random_plaintext(degree, t, &mut rng);
            let pt_4 = Plaintext::generate_random_plaintext(degree, t, &mut rng);

            let ct_1 = pt_1.encrypt(&public_key, std_dev, &mut rng);
            let ct_2 = pt_2.encrypt(&public_key, std_dev, &mut rng);
            let ct_3 = pt_3.encrypt(&public_key, std_dev, &mut rng);
            let ct_4 = pt_4.encrypt(&public_key, std_dev, &mut rng);

            let expr_ct = ct_1 * (ct_2, &ek_1) + ct_3 * (ct_4, &ek_1);
            let expr_pt = expr_ct.decrypt(&secret_key);

            let expected_pt = (pt_1.m() * pt_2.m() + pt_3.m() * pt_4.m()) % (t, degree);
            assert_eq!(expr_pt.m(), expected_pt);
        }
    }

    #[test]
    fn end_to_end_test_v2() {
        // TODO: fails
        for _ in 0..1000 {
            let q = 65536;
            let t = 16;
            let std_dev = 2.0;
            let degree = 4;
            let rlk_p = 2_i64.pow(13) * q;
            let mut rng = rand::rngs::StdRng::seed_from_u64(23);

            let secret_key = SecretKey::new(degree, &mut rng);
            let public_key = secret_key.generate_pk(q, std_dev, &mut rng);
            let ek_2 = secret_key.generate_ek_v1(q, std_dev, &mut rng, rlk_p);

            let pt_1 = Plaintext::generate_random_plaintext(degree, t, &mut rng);
            let pt_2 = Plaintext::generate_random_plaintext(degree, t, &mut rng);
            let pt_3 = Plaintext::generate_random_plaintext(degree, t, &mut rng);
            let pt_4 = Plaintext::generate_random_plaintext(degree, t, &mut rng);

            let ct_1 = pt_1.encrypt(&public_key, std_dev, &mut rng);
            let ct_2 = pt_2.encrypt(&public_key, std_dev, &mut rng);
            let ct_3 = pt_3.encrypt(&public_key, std_dev, &mut rng);
            let ct_4 = pt_4.encrypt(&public_key, std_dev, &mut rng);

            let expr_ct = ct_1 * (ct_2, &ek_2) + ct_3 * (ct_4, &ek_2);
            let expr_pt = expr_ct.decrypt(&secret_key);

            let expected_pt = (pt_1.m() * pt_2.m() + pt_3.m() * pt_4.m()) % (t, degree);
            assert_eq!(expr_pt.m(), expected_pt);
        }
    }
}
