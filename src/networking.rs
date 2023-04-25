mod async_encrypted_tcp_connection_handler {

    use std::io;
    use rsa::{
        RsaPublicKey,
        Pkcs1v15Encrypt,
        PublicKey,
        pkcs8::{
            DecodePrivateKey,
            DecodePublicKey,
        },
    };
    use aes_gcm_siv::{
        Aes256GcmSiv,
        Nonce,
        KeyInit
    };
    use tokio::{
        net::TcpStream,
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
                            format!("[ERROR] failed to encrypt the AES key using the client's public key\n{}", error)
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
    
        // message structure
        // repeat-byte (0 or 1), 12-bytes nonce, 16*x bytes message (AES compability)
    
        return Ok(());
    }
}

mod asnyc_tcp_connection_listener {
    use tokio::{
        net::TcpListener,
        time::sleep,
    };


    async fn listen(listening_port: usize) {
        loop {
            let listener : TcpListener = match TcpListener::bind(&format!("{}:{}", "0.0.0.0", listening_port)).await {
                Ok(listener) => listener,
                Err(..) => {
                    sleep(tokio::time::Duration::from_secs(5)).await;
                    continue;
                }
            };
            loop {
                let socket =  match listener.accept().await {
                    Ok(sock) => sock,
                    Err(..) => continue,
                };
                // process the socket
            }
        }
    }
}

mod async_encrypted_tcp_client {
    use std::io;
    use rsa::{
        RsaPrivateKey,
        Pkcs1v15Encrypt,
    };
    use aes_gcm_siv::{
        Aes256GcmSiv,
        Nonce,
        KeyInit
    };
    use tokio::{
        net::TcpStream,
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
    
    async fn connect(address:&str, client_private_key:&RsaPrivateKey) -> io::Result<()> {
        let mut stream: TcpStream = TcpStream::connect(address).await?;
        let mut rng: ThreadRng = thread_rng();
        // authentication using RSA
        {
            // 512 bytes for a 4096-bit rsa key
            let mut buffer : [u8; 512] = [0; 512];
            stream.read(&mut buffer).await?;
            let token : Vec<u8> = client_private_key.decrypt(Pkcs1v15Encrypt, &buffer).unwrap();
            stream.write(&token).await?;
            stream.flush().await?;
        }

        let cipher = {
            // 512 bytes for a 4096-bit rsa key
            let mut buffer : [u8; 512] = [0; 512];
            stream.read(&mut buffer).await?;
            let key : Vec<u8> = match client_private_key.decrypt(Pkcs1v15Encrypt, &buffer) {
                Ok(key) => key,
                Err(..) => return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "[ERROR] failed to create AES key")),
            };
            match Aes256GcmSiv::new_from_slice(&key[..]) {
                Ok(cipher) => cipher,
                Err(..) => return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "[ERROR] failed to create AES key")),
            }
        };

        // always create a new different nonce and send it alongside your message
        let nonce = {
        let mut nonce_slice: [u8; 12] = [0; 12]; rng.fill_bytes(&mut nonce_slice);
            Nonce::clone_from_slice(&nonce_slice)
        };
            
        // message structure
        // repeat-byte (0 or 1), 12-bytes nonce, 16*x bytes message (AES compability)

        return Ok(());
    }
}