use ring::{aead, pbkdf2};
use std::fs::{self, File};
use std::io::{Read};
use std::path::Path;

const SALT: &[u8; 16] = b"passwordmanagerr"; // Salt para PBKDF2
const KEY_LEN: usize = 32; // Longitud de la clave para AES-256

pub struct PasswordManager {
    current_user: Option<String>,
}

impl PasswordManager {
    pub fn new() -> Self {
        PasswordManager { current_user: None }
    }

    pub fn user(&mut self, username: &str, password: &str) -> Result<(), String> {
        let file_path = format!("{}.enc", username);
        let path = Path::new(&file_path);

        if path.exists() {
            // El usuario ya existe, intentar desencriptar
            match self.decrypt_file(&file_path, password) {
                Ok(_) => {
                    self.current_user = Some(username.to_string());
                    println!("Logged in as {}", username);
                    Ok(())
                }
                Err(_) => Err("Incorrect password".to_string()),
            }
        } else {
            // Nuevo usuario, crear archivo encriptado
            let content = "Initial content".as_bytes();
            match self.encrypt_and_save(content, &file_path, password) {
                Ok(_) => {
                    self.current_user = Some(username.to_string());
                    println!("New user {} created and logged in", username);
                    Ok(())
                }
                Err(e) => Err(format!("Failed to create user: {}", e)),
            }
        }
    }

    fn derive_key(password: &str) -> [u8; KEY_LEN] {
        let mut key = [0u8; KEY_LEN];
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            std::num::NonZeroU32::new(100_000).unwrap(),
            SALT,
            password.as_bytes(),
            &mut key,
        );
        key
    }

    fn encrypt_and_save(&self, data: &[u8], file_path: &str, password: &str) -> Result<(), String> {
        let key = Self::derive_key(password);
        let sealing_key = aead::UnboundKey::new(&aead::AES_256_GCM, &key)
            .map_err(|_| "Failed to create sealing key")?;
        let sealing_key = aead::LessSafeKey::new(sealing_key);

        let nonce = aead::Nonce::assume_unique_for_key([0u8; 12]);
        let mut in_out = data.to_vec();
        sealing_key
            .seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut in_out)
            .map_err(|_| "Encryption failed")?;

        fs::write(file_path, &in_out).map_err(|_| "Failed to write file")?;
        Ok(())
    }

    fn decrypt_file(&self, file_path: &str, password: &str) -> Result<Vec<u8>, String> {
        let key = Self::derive_key(password);
        let opening_key = aead::UnboundKey::new(&aead::AES_256_GCM, &key)
            .map_err(|_| "Failed to create opening key")?;
        let opening_key = aead::LessSafeKey::new(opening_key);

        let mut file = File::open(file_path).map_err(|_| "Failed to open file")?;
        let mut encrypted_data = Vec::new();
        file.read_to_end(&mut encrypted_data)
            .map_err(|_| "Failed to read file")?;

        let nonce = aead::Nonce::assume_unique_for_key([0u8; 12]);
        let decrypted_data = opening_key
            .open_in_place(nonce, aead::Aad::empty(), &mut encrypted_data)
            .map_err(|_| "Decryption failed")?;

        Ok(decrypted_data.to_vec())
    }
}