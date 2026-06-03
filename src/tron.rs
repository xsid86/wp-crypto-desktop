use serde::Deserialize;

const NILE_BASE: &str = "https://nile.trongrid.io";

/// Ответ ноды на запрос аккаунта. Поля, которые нам интересны сейчас.
/// (balance приходит в SUN — 1 TRX = 1_000_000 SUN)
#[derive(Deserialize, Debug)]
struct AccountResponse {
    #[serde(default)]
    balance: i64,
}

/// Запрашивает баланс TRX (в SUN) для адреса на Nile testnet.
pub async fn get_balance(
    api_key: &str,
    address_base58: &str,
) -> Result<i64, Box<dyn std::error::Error>> {
    let url = format!("{}/wallet/getaccount", NILE_BASE);

    let client = reqwest::Client::new();
    let response = client
        .post(&url)
        .header("TRON-PRO-API-KEY", api_key)
        .json(&serde_json::json!({
            "address": address_base58,
            "visible": true   // true = адрес в формате Base58 (T...), а не hex
        }))
        .send()
        .await?;

    let status = response.status();
    let text = response.text().await?;

    println!("--- Ответ ноды (getaccount) ---");
    println!("HTTP {}", status);
    println!("{}", text);

    // Пытаемся распарсить баланс (если аккаунт новый/пустой, ответ может быть {} )
    let parsed: AccountResponse =
        serde_json::from_str(&text).unwrap_or(AccountResponse { balance: 0 });

    Ok(parsed.balance)
}

/// Преобразует Tron Base58-адрес (T...) в hex 20 байт без префикса 0x41.
/// Нужно для кодирования адресов в параметрах вызова контракта.
pub fn base58_to_hex20(address_base58: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Base58Check -> байты: [0x41][20 байт адреса][4 байта checksum]
    let decoded = bs58::decode(address_base58).with_check(None).into_vec()?;
    // decoded[0] = 0x41 (префикс), дальше 20 байт адреса.
    if decoded.len() != 21 || decoded[0] != 0x41 {
        return Err("Invalid Tron address format".into());
    }
    let addr20 = &decoded[1..]; // 20 байт без префикса
    Ok(hex::encode(addr20))
}

/// Читает баланс TRC20-токена (balanceOf) для адреса.
/// Возвращает «сырой» баланс в базовых единицах (для USDT надо делить на 10^6).
pub async fn get_trc20_balance(
    api_key: &str,
    contract_base58: &str,
    owner_base58: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let url = format!("{}/wallet/triggerconstantcontract", NILE_BASE);

    // Параметр balanceOf(address): 20 байт адреса, дополненные слева нулями до 32 байт (64 hex).
    let owner_hex20 = base58_to_hex20(owner_base58)?;
    let parameter = format!("{:0>64}", owner_hex20); // паддинг нулями слева до 64 символов

    let client = reqwest::Client::new();
    let response = client
        .post(&url)
        .header("TRON-PRO-API-KEY", api_key)
        .json(&serde_json::json!({
            "owner_address": owner_base58,
            "contract_address": contract_base58,
            "function_selector": "balanceOf(address)",
            "parameter": parameter,
            "visible": true
        }))
        .send()
        .await?;

    let status = response.status();
    let text = response.text().await?;

    println!("--- Ответ ноды (triggerconstantcontract / balanceOf) ---");
    println!("HTTP {}", status);
    println!("{}", text);

    Ok(text)
}

/// Кодирует u128-сумму в 32-байтное hex-поле (64 символа), нули слева. Для uint256-параметра.
fn encode_uint256(amount: u128) -> String {
    format!("{:0>64x}", amount) // x = hex, 0> = нули слева до 64 символов
}

/// Собирает НЕПОДПИСАННУЮ транзакцию transfer(to, amount).
/// Возвращает (txID, объект transaction как есть) — транзакцию потом подпишем и вернём ноде.
pub async fn build_trc20_transfer(
    api_key: &str,
    contract_base58: &str,
    owner_base58: &str,
    to_base58: &str,
    amount: u128,
    fee_limit_sun: i64,
) -> Result<(String, serde_json::Value), Box<dyn std::error::Error>> {
    let url = format!("{}/wallet/triggersmartcontract", NILE_BASE);

    let to_hex20 = base58_to_hex20(to_base58)?;
    let param_address = format!("{:0>64}", to_hex20);
    let param_amount = encode_uint256(amount);
    let parameter = format!("{}{}", param_address, param_amount);

    let client = reqwest::Client::new();
    let response = client
        .post(&url)
        .header("TRON-PRO-API-KEY", api_key)
        .json(&serde_json::json!({
            "owner_address": owner_base58,
            "contract_address": contract_base58,
            "function_selector": "transfer(address,uint256)",
            "parameter": parameter,
            "fee_limit": fee_limit_sun,
            "call_value": 0,
            "visible": true
        }))
        .send()
        .await?;

    let text = response.text().await?;

    // Парсим ответ в «любой JSON».
    let json: serde_json::Value = serde_json::from_str(&text)?;

    // Проверяем, что сборка успешна.
    let ok = json
        .get("result")
        .and_then(|r| r.get("result"))
        .and_then(|b| b.as_bool())
        .unwrap_or(false);

    if !ok {
        return Err(format!("Сборка транзакции не удалась: {}", text).into());
    }

    // Достаём объект transaction (его целиком вернём ноде с подписью).
    let transaction = json
        .get("transaction")
        .ok_or("В ответе нет поля transaction")?
        .clone();

    // Достаём txID для подписи.
    let txid = transaction
        .get("txID")
        .and_then(|t| t.as_str())
        .ok_or("В transaction нет txID")?
        .to_string();

    Ok((txid, transaction))
}

/// Отправляет подписанную транзакцию в сеть.
/// Берёт объект transaction (как вернула нода) и добавляет в него поле signature.
pub async fn broadcast_transaction(
    api_key: &str,
    mut transaction: serde_json::Value,
    signature_hex: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    // Добавляем подпись как массив (Tron допускает несколько подписей; у нас одна).
    transaction["signature"] = serde_json::json!([signature_hex]);

    let url = format!("{}/wallet/broadcasttransaction", NILE_BASE);

    let client = reqwest::Client::new();
    let response = client
        .post(&url)
        .header("TRON-PRO-API-KEY", api_key)
        .json(&transaction)
        .send()
        .await?;

    let status = response.status();
    let text = response.text().await?;

    println!("--- Ответ ноды (broadcasttransaction) ---");
    println!("HTTP {}", status);
    println!("{}", text);

    Ok(text)
}
