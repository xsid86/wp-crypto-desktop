//! Боевой поток свипа TRC20: собрать -> сверить адрес -> подписать -> отправить.
//! Сетевые вызовы берёт из tron.rs, криптографию — из crypto.rs.

use crate::config::Config;
use crate::{crypto, tron};

/// Результат успешного свипа.
pub struct SweepResult {
    pub txid: String,
}

/// Выполняет перевод `amount` базовых единиц токена с адреса `owner` (index `index`)
/// на `to`. Перед подписью СВЕРЯЕТ адрес из ключа с owner — иначе отказ.
///
/// Возвращает txID при успехе.
pub async fn sweep_trc20(
    config: &Config,
    mnemonic: &str,
    index: u32,
    owner: &str,
    to: &str,
    amount: u128,
    fee_limit_sun: i64,
) -> Result<SweepResult, Box<dyn std::error::Error>> {
    // 1. Собрать неподписанную транзакцию.
    let (txid, transaction) = tron::build_trc20_transfer(
        &config.api_key,
        &config.usdt_contract,
        owner,
        to,
        amount,
        fee_limit_sun,
    )
    .await?;

    // 2. Достать ключ и СВЕРИТЬ адрес (железное правило безопасности).
    let privkey = crypto::derive_tron_privkey(mnemonic, index)?;
    let derived = crypto::tron_address_from_privkey(&privkey)?;
    if derived != owner {
        return Err(format!(
            "Address mismatch: derived {} != owner {} — sweep aborted",
            derived, owner
        )
        .into());
    }

    // 3. Подписать txID.
    let signature = crypto::sign_txid(&privkey, &txid)?;

    // 4. Отправить.
    tron::broadcast_transaction(&config.api_key, transaction, &signature).await?;

    Ok(SweepResult { txid })
}
