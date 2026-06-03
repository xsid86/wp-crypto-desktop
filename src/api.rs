use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use crate::models::queue::{QueueItem, QueueResponse};

type HmacSha256 = Hmac<Sha256>;

/// Считает HMAC-подпись по канонической строке:
///   timestamp \n METHOD \n route \n payload
pub fn sign_request(
    secret: &str,
    timestamp: &str,
    method: &str,
    route: &str,
    payload: &str,
) -> String {
    let canonical = format!("{}\n{}\n{}\n{}", timestamp, method, route, payload);

    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take a key of any size");
    mac.update(canonical.as_bytes());
    let result = mac.finalize().into_bytes();

    hex::encode(result)
}

/// Запрашивает очередь свипа и возвращает распарсенный список записей.
pub async fn fetch_queue(
    base_url: &str,
    api_key: &str,
    api_secret: &str,
) -> Result<Vec<QueueItem>, Box<dyn std::error::Error>> {
    let route = "/wpcrypto/v1/sweep/queue";
    let method = "GET";

    let mut params: Vec<(&str, String)> = vec![
        ("since_id", "0".to_string()),
        ("limit", "50".to_string()),
    ];
    params.sort_by(|a, b| a.0.cmp(b.0));

    let payload = params
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<String>>()
        .join("&");

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs()
        .to_string();

    let signature = sign_request(api_secret, &timestamp, method, route, &payload);
    let url = format!("{}/wp-json{}?{}", base_url, route, payload);

    let client = reqwest::Client::new();
    let response = client
        .get(&url)
        .header("X-WPC-Key", api_key)
        .header("X-WPC-Timestamp", &timestamp)
        .header("X-WPC-Signature", &signature)
        .send()
        .await?;

    let text = response.text().await?;

    // Парсим в структуру. Если success=false — ошибка.
    let parsed: QueueResponse = serde_json::from_str(&text)
        .map_err(|e| format!("Не удалось разобрать ответ очереди: {} | тело: {}", e, text))?;

    if !parsed.success {
        return Err(format!("Сервер вернул success=false: {}", text).into());
    }

    Ok(parsed.data.items)
}
