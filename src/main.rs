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
mod models;

use config::Config;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base_url = "http://wpcrypto.loc";
    let api_key = "wpc_live_3f9a2b7c8d1e4f60";
    let api_secret = "b1946ac92492d2347c6235b4d2611184a3e0f9c5d7e8a2b1";

    println!("Читаем очередь свипа...");
    let items = api::fetch_queue(base_url, api_key, api_secret).await?;

    println!("Записей в очереди: {}", items.len());
    for item in &items {
        println!(
            "  #{}  {} {}  адрес={} index={} баланс={} статус={}",
            item.id, item.symbol, item.network_code,
            item.address, item.derivation_index, item.balance, item.status
        );
    }

    Ok(())
}