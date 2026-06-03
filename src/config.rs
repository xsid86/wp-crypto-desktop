//! Конфигурация приложения. Пока с тестовыми значениями (Nile testnet).
//! Позже источником секретов станут зашифрованный vault + настройки из GUI.

/// Параметры сети и свипа в одном месте — никаких «магических строк» в логике.
pub struct Config {
    pub api_key: String,       // TronGrid API-ключ
    pub node_base: String,     // базовый URL ноды (Nile / mainnet)
    pub usdt_contract: String, // адрес USDT-контракта в выбранной сети
}

impl Config {
    /// Тестовая конфигурация под Nile testnet.
    pub fn nile_test() -> Self {
        Config {
            api_key: "2df1390f-4a08-4651-83d2-0f80b6729fa1".to_string(),
            node_base: "https://nile.trongrid.io".to_string(),
            usdt_contract: "TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf".to_string(),
        }
    }
}
