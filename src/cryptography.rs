mod print_rsa_key_pair_pem {
    use rsa::{
        RsaPrivateKey,
        RsaPublicKey,
        pkcs8::{
            EncodePrivateKey,
            EncodePublicKey,
        },
    };
    use rand::thread_rng;

    fn generate() {
        let mut rng = thread_rng();
    
        let bits = 4096;
        let private_key = RsaPrivateKey::new(&mut rng, bits).unwrap();
        let public_key = RsaPublicKey::from(&private_key);
        println!("{}\n\n{}",
            private_key.to_pkcs8_pem(rsa::pkcs8::LineEnding::CRLF).unwrap().as_str(),
            public_key.to_public_key_pem(rsa::pkcs8::LineEnding::CRLF).unwrap().as_str(),
        );
    }
}