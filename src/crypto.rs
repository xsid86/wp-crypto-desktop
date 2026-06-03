use bip32::{DerivationPath, XPrv};
use bip39::Mnemonic;
use k256::ecdsa::{RecoveryId, Signature, SigningKey};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use std::str::FromStr;
use tiny_keccak::{Hasher, Keccak};
use zeroize::Zeroizing;

/// Деривирует приватный ключ Tron по пути m/44'/195'/0'/0/{index}.
/// Возвращает 32 байта приватного ключа в самозатирающейся обёртке.
pub fn derive_tron_privkey(
    mnemonic_phrase: &str,
    index: u32,
) -> Result<Zeroizing<[u8; 32]>, Box<dyn std::error::Error>> {
    let mnemonic = Mnemonic::parse(mnemonic_phrase)?;
    let seed = mnemonic.to_seed("");

    let path_str = format!("m/44'/195'/0'/0/{}", index);
    let path = DerivationPath::from_str(&path_str)?;

    let mut key = XPrv::new(&seed)?;
    for child in path.into_iter() {
        key = key.derive_child(child)?;
    }

    // Достаём сырые 32 байта приватного ключа.
    let privkey_bytes: [u8; 32] = key.private_key().to_bytes().into();

    Ok(Zeroizing::new(privkey_bytes))
}

/// Строит Tron-адрес из 32-байтного приватного ключа.
/// secp256k1 pubkey -> Keccak-256 -> последние 20 байт -> префикс 0x41 -> Base58Check.
pub fn tron_address_from_privkey(privkey: &[u8; 32]) -> Result<String, Box<dyn std::error::Error>> {
    // Приватный ключ -> публичный ключ (k256).
    let signing_key = k256::SecretKey::from_slice(privkey)?;
    let public_key = signing_key.public_key();

    // Несжатые координаты X||Y (64 байта, без префикса 0x04).
    let encoded = public_key.to_encoded_point(false);
    let xy = &encoded.as_bytes()[1..];

    // Keccak-256.
    let mut keccak = Keccak::v256();
    let mut hash = [0u8; 32];
    keccak.update(xy);
    keccak.finalize(&mut hash);

    // последние 20 байт + префикс 0x41 -> Base58Check.
    let mut raw_address = Vec::with_capacity(21);
    raw_address.push(0x41);
    raw_address.extend_from_slice(&hash[12..]);

    Ok(bs58::encode(raw_address).with_check().into_string())
}

/// Удобная обёртка: по мнемонике и индексу сразу даёт адрес (как раньше).
pub fn derive_tron_address(
    mnemonic_phrase: &str,
    index: u32,
) -> Result<String, Box<dyn std::error::Error>> {
    let privkey = derive_tron_privkey(mnemonic_phrase, index)?;
    tron_address_from_privkey(&privkey)
}

/// Подписывает txID (готовый 32-байтный хэш) приватным ключом.
/// Возвращает recoverable-подпись 65 байт (r||s||recovery_id) в hex — формат, который ждёт Tron.
///
/// ВАЖНО: txID уже является хэшем (SHA-256 от raw_data), поэтому подписываем его
/// как prehashed digest — БЕЗ повторного хеширования.
pub fn sign_txid(privkey: &[u8; 32], txid_hex: &str) -> Result<String, Box<dyn std::error::Error>> {
    // txID из hex-строки в 32 байта.
    let txid_bytes = hex::decode(txid_hex)?;
    if txid_bytes.len() != 32 {
        return Err("txID must be 32 bytes".into());
    }

    // Поднимаем приватный ключ.
    let signing_key = SigningKey::from_slice(privkey)?;

    // Подписываем УЖЕ ГОТОВЫЙ хэш (prehash), получаем подпись + recovery id.
    let (signature, recovery_id): (Signature, RecoveryId) =
        signing_key.sign_prehash_recoverable(&txid_bytes)?;

    // Собираем 65 байт: r(32) + s(32) + recovery_id(1).
    let mut sig_bytes = signature.to_bytes().to_vec(); // 64 байта: r||s
    sig_bytes.push(recovery_id.to_byte()); // +1 байт recovery

    Ok(hex::encode(sig_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ВПИШИ свою тестовую мнемонику локально. Не присылай в чат.
    // Мнемоника читается из src/test_mnemonic.txt (файл в .gitignore, не в репозитории).
    // include_str! вставляет содержимое файла на этапе компиляции. .trim() убирает
    // возможный перевод строки в конце.
    const TEST_MNEMONIC: &str = include_str!("test_mnemonic.txt");
    const EXPECTED_ADDRESS: &str = "TH7RSpHmJteMH3ZKyXHxWGF2ZpC2R3E2ds";

    #[test]
    fn privkey_yields_correct_address() {
        let index = 1u32;
        let privkey = derive_tron_privkey(TEST_MNEMONIC, index).expect("derive privkey failed");
        let address = tron_address_from_privkey(&privkey).expect("address failed");

        assert_eq!(
            address, EXPECTED_ADDRESS,
            "адрес из приватного ключа должен совпасть с эталоном из БД"
        );
    }
}
