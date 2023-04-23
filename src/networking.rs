

// ASYNC ENCRYPTED TCP SERVER

use std::io;
use rsa::{
    RsaPublicKey,
    Pkcs1v15Encrypt,
    PublicKey
};
use aes_gcm_siv::{
    Aes256GcmSiv,
    Nonce,
    KeyInit
};
use tokio::{
    net::{
        TcpListener,
        TcpStream,
    },
    io::{
        AsyncWriteExt,
        AsyncReadExt,
    },
};
use rand::{
    rngs::ThreadRng,
    RngCore,
    thread_rng,
};

async fn handle_client(mut stream: TcpStream, client_public_key: &RsaPublicKey) -> io::Result<()> {
    let mut rng: ThreadRng = thread_rng();

    // authentication using RSA
    {
        // creates an array containing 128 random 8-bit unsigned integers
        let mut random_token: [u8; 128] = [0; 128]; rng.fill_bytes(&mut random_token);
        // sends the client the array encrypted with their rsa public key
        // the client's rsa key must be known beforehand
        stream.write(
            match &client_public_key.encrypt(&mut rng, Pkcs1v15Encrypt, &random_token) {
                Ok(bytes) => bytes,
                Err(error) => {
                    stream.shutdown().await?;
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        format!("[ERROR] failed to encrypt the auth token using the client's public key\n{}", error)
                    ));
                },
            }
        ).await?;
        // creates a buffer to receive the decrypted bytes
        let mut token_buffer: [u8; 128] = [0; 128];
        // receives the bytes from the client
        stream.read(&mut token_buffer).await?;
        // verifies the bytes
        if token_buffer != random_token {
            stream.shutdown().await?;
            return Ok(());
        }
    }

    // generates a random AES key
    let cipher: Aes256GcmSiv = {
        let key = Aes256GcmSiv::generate_key(&mut rng);
        stream.write(
            match&client_public_key.encrypt(&mut rng, Pkcs1v15Encrypt, &key as &[u8]) {
                Ok(bytes) => bytes,
                Err(error) => {
                    stream.shutdown().await?;
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        format!("[ERROR] failed to encrypt the aes key using the client's public key\n{}", error)
                    ));
                },
            }).await?;
        Aes256GcmSiv::new(&key)
    };
    
    // always create a new different nonce and send it alongside your message
    let nonce = {
        let mut nonce_slice: [u8; 12] = [0; 12]; rng.fill_bytes(&mut nonce_slice);
        Nonce::clone_from_slice(&nonce_slice)
    };

    return Ok(());

}
