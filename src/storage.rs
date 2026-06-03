use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::Argon2;
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use directories::ProjectDirs;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use zeroize::{Zeroize, Zeroizing};

/// Зашифрованное хранилище в виде, который ложится на диск (JSON).
/// Все поля, кроме пароля, не секретны и хранятся открыто.
#[derive(Serialize, Deserialize)]
pub struct Vault {
    pub version: u8,        // версия формата — на будущее
    pub kdf: String,        // какой KDF использован
    pub salt: String,       // соль для Argon2 (base64)
    pub nonce: String,      // nonce для AES-GCM (base64)
    pub ciphertext: String, // шифротекст мнемоники + тег (base64)
}

const VAULT_VERSION: u8 = 1;

/// Выводит 32-байтный ключ шифрования из пароля и соли через Argon2id.
fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let argon2 = Argon2::default(); // Argon2id с разумными параметрами по умолчанию
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| format!("Argon2 error: {}", e))?;
    Ok(key)
}

/// Шифрует мнемонику паролем. Возвращает Vault, готовый к сериализации в JSON.
pub fn encrypt_seed(mnemonic: &str, password: &str) -> Result<Vault, Box<dyn std::error::Error>> {
    // Случайные соль и nonce.
    let mut salt = [0u8; 16];
    let mut nonce_bytes = [0u8; 12]; // AES-GCM требует 12-байтный nonce
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    // Ключ из пароля.
    let mut key_bytes = derive_key(password, &salt)?;

    // Шифруем.
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, mnemonic.as_bytes())
        .map_err(|e| format!("Encrypt error: {}", e))?;

    // Затираем ключ из памяти сразу после использования.
    key_bytes.zeroize();

    Ok(Vault {
        version: VAULT_VERSION,
        kdf: "argon2id".to_string(),
        salt: B64.encode(salt),
        nonce: B64.encode(nonce_bytes),
        ciphertext: B64.encode(ciphertext),
    })
}

/// Расшифровывает мнемонику из Vault по паролю.
/// Возвращает её в самозатирающейся обёртке: когда значение выйдет из
/// области видимости, байты мнемоники будут перезаписаны нулями в памяти.
/// Неверный пароль или повреждённый файл -> ошибка (GCM не даст «тихий мусор»).
pub fn decrypt_seed(
    vault: &Vault,
    password: &str,
) -> Result<Zeroizing<String>, Box<dyn std::error::Error>> {
    let salt = B64.decode(&vault.salt)?;
    let nonce_bytes = B64.decode(&vault.nonce)?;
    let ciphertext = B64.decode(&vault.ciphertext)?;

    let mut key_bytes = derive_key(password, &salt)?;

    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| "Decrypt failed: wrong password or corrupted vault".to_string())?;

    key_bytes.zeroize();

    let mnemonic = String::from_utf8(plaintext)?;
    Ok(Zeroizing::new(mnemonic))
}

/// Возвращает путь к файлу-хранилищу в системной папке конфигов приложения.
/// Windows: %APPDATA%\wpcrypto\signer\vault.json и аналоги на других ОС.
fn vault_path() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let dirs =
        ProjectDirs::from("dev", "wpcrypto", "signer").ok_or("Cannot resolve config directory")?;
    let dir = dirs.config_dir();
    fs::create_dir_all(dir)?; // создаём папку, если её ещё нет
    Ok(dir.join("vault.json"))
}

/// Есть ли уже сохранённое хранилище.
pub fn vault_exists() -> bool {
    match vault_path() {
        Ok(p) => p.exists(),
        Err(_) => false,
    }
}

/// Сериализует Vault в JSON и записывает в файл-хранилище.
pub fn save_vault(vault: &Vault) -> Result<(), Box<dyn std::error::Error>> {
    let path = vault_path()?;
    let json = serde_json::to_string_pretty(vault)?;
    fs::write(&path, json)?;
    Ok(())
}

/// Читает файл-хранилище и парсит JSON обратно в Vault.
pub fn load_vault() -> Result<Vault, Box<dyn std::error::Error>> {
    let path = vault_path()?;
    let json = fs::read_to_string(&path)?;
    let vault: Vault = serde_json::from_str(&json)?;
    Ok(vault)
}

// --- Тесты модуля ---
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_correct_password() {
        let mnemonic = "test test test test test test test test test test test test";
        let password = "correct horse battery staple";

        let vault = encrypt_seed(mnemonic, password).expect("encrypt failed");
        let decrypted = decrypt_seed(&vault, password).expect("decrypt failed");

        assert_eq!(
            decrypted.as_str(),
            mnemonic,
            "расшифрованная фраза должна совпасть"
        );
    }

    #[test]
    fn wrong_password_fails() {
        let mnemonic = "test test test test test test test test test test test test";
        let vault = encrypt_seed(mnemonic, "right-password").expect("encrypt failed");

        let result = decrypt_seed(&vault, "wrong-password");
        assert!(
            result.is_err(),
            "неверный пароль должен давать ошибку, а не мусор"
        );
    }

    #[test]
    fn save_load_roundtrip() {
        let mnemonic = "test test test test test test test test test test test test";
        let password = "file-password";

        let vault = encrypt_seed(mnemonic, password).expect("encrypt failed");
        save_vault(&vault).expect("save failed");

        let loaded = load_vault().expect("load failed");
        let decrypted = decrypt_seed(&loaded, password).expect("decrypt failed");

        assert_eq!(
            decrypted.as_str(),
            mnemonic,
            "после сохранения и загрузки фраза должна совпасть"
        );
    }
}
