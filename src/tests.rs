#[cfg(test)]
mod tests {
    use crate::keygen::SecretKey;
    use crate::plaintext::Plaintext;
    use rand::SeedableRng;

    #[test]
    fn test_encryption() {
        let iter_amount = 10;

        let degree = 100;
        let t_list = vec![2, 4, 8, 16, 32];
        let q = 65536;
        let std_dev = 3.2;

        let mut rng = rand::rngs::StdRng::seed_from_u64(18);

        for t in t_list.iter() {
            for i in (0..iter_amount) {
                println!("--- #{} encryption test for t={} ---", i, t);
                let sk = SecretKey::generate_sk(degree, &mut rng);
                let pk = sk.generate_pk(q, std_dev, &mut rng);
                let plaintext = Plaintext::generate_random_plaintext(degree, *t, &mut rng);
                println!("plaintext: {}", plaintext.M());
                let encrypted = plaintext.encrypt(&pk, std_dev, &mut rng);
                println!("ciphertext: {}", encrypted.c_1);
                let decrypted = encrypted.decrypt(&sk);
                println!("decrypted: {}", decrypted.M());
                assert_eq!(decrypted.M(), plaintext.M() % (*t, degree));
            }
        }
    }
}
