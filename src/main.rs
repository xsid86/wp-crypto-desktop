// Проект в активной разработке: часть модулей (хранилище, чтение баланса, API-клиент)
// уже готова и протестирована, но ещё не подключена к боевому потоку — это задел,
// не мёртвый код. Глушим соответствующие предупреждения на уровне крейта.
#![allow(dead_code)]
#![allow(deprecated)]
mod api;
mod config;
mod crypto;
mod signer;
mod storage;
mod tron;

use config::Config;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Тестовый прогон свипа на Nile. В бою параметры придут из очереди + vault.
    let config = Config::nile_test();

    // Тестовая мнемоника (на этапе GUI заменится расшифровкой vault по паролю).
    let mnemonic = include_str!("test_mnemonic.txt").trim_end();

    let index = 1u32;
    let owner = "TH7RSpHmJteMH3ZKyXHxWGF2ZpC2R3E2ds";
    let to = "TB9AMjV3gq6XEJZm7x7y5nFjNHCVnR24uj";
    let amount = 1_000_000u128; // 1 USDT
    let fee_limit = 100_000_000i64; // 100 TRX потолок

    println!("Свип 1 USDT: {} -> {}", owner, to);

    let result =
        signer::sweep_trc20(&config, mnemonic, index, owner, to, amount, fee_limit).await?;

    println!("Готово. txID: {}", result.txid);
    println!(
        "Проверь: https://nile.tronscan.org/#/transaction/{}",
        result.txid
    );

    Ok(())
}
