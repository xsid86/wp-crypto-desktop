//! Структуры данных очереди свипа (ответ GET /sweep/queue).

use serde::Deserialize;

/// Один элемент очереди свипа.
#[derive(Deserialize, Debug, Clone)]
pub struct QueueItem {
    pub id: u64,
    pub network_code: String,
    pub family: String,
    pub native_symbol: String,
    pub symbol: String,
    pub contract_address: Option<String>,
    pub decimals: u32,
    pub address: String,
    pub derivation_path: String,
    pub derivation_index: u32,
    pub funding_address: Option<String>,
    pub balance: String,
    pub status: String,
    pub external_order_id: String,
}

/// Обёртка ответа: {"success":..,"data":{"items":[..],"count":..}}
#[derive(Deserialize, Debug)]
pub struct QueueResponse {
    pub success: bool,
    pub data: QueueData,
}

#[derive(Deserialize, Debug)]
pub struct QueueData {
    pub items: Vec<QueueItem>,
    pub count: u32,
}