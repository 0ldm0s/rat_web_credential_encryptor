//! 加密登录示例服务器
//!
//! 展示如何使用 rat_web_credential_encryptor 进行安全的登录处理

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use rat_web_credential_encryptor::{SessionManager, decrypt_string_ctr};
use base64ct::Encoding;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use std::collections::HashMap;
use std::sync::Mutex;

/// Demo解密详情（存储在内存中）
#[derive(Clone)]
struct DemoDecryptResult {
    key: String,
    encrypted_data: String,
    username: String,
    password: String,
}

/// 服务器状态
#[derive(Clone)]
struct ServerState {
    /// 会话管理器
    session_manager: Arc<SessionManager>,
    /// Demo结果存储：demo_id -> 解密详情
    /// ⚠️ 仅用于demo演示，生产环境不应存储明文密码
    demo_results: Arc<Mutex<HashMap<String, DemoDecryptResult>>>,
}

/// 响应类型
#[derive(serde::Serialize)]
struct ApiResponse<T> {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// 密钥响应
#[derive(serde::Serialize)]
struct KeyResponse {
    /// Base64 编码的 AES 密钥
    key: String,
    /// 会话 ID
    session_id: String,
}

/// 登录响应
#[derive(serde::Serialize)]
struct LoginResponse {
    /// Demo ID，用于获取解密详情（仅demo用途）
    demo_id: String,
}

/// Demo解密详情响应
///
/// ⚠️ 警告：此结构仅用于demo演示，生产环境绝对不能返回明文密码和密钥！
#[derive(serde::Serialize)]
struct DemoDecryptResponse {
    /// Base64 编码的密钥
    key: String,
    /// 加密数据
    encrypted_data: String,
    /// 解密后的用户名
    username: String,
    /// 解密后的密码（⚠️ 生产环境严禁返回）
    password: String,
}

async fn handle_request(
    req: Request<hyper::body::Incoming>,
    state: ServerState,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let method = req.method().clone();
    let path = req.uri().path();

    println!("收到请求: {} {}", method, path);

    match (method.as_str(), path) {
        // 获取加密密钥
        ("GET", "/api/key") => {
            // 创建新会话，生成随机 AES 密钥
            let (session_id, key_bytes) = state.session_manager.create_session();

            // 将密钥转为 Base64 传输
            let key_b64 = base64ct::Base64::encode_string(&key_bytes);

            println!("创建新会话: {}", session_id);

            let response = KeyResponse {
                key: key_b64,
                session_id: session_id.clone(),
            };

            Ok(json_response(ApiResponse {
                success: true,
                data: Some(response),
                error: None,
            }))
        }

        // 登录处理
        ("POST", "/api/login") => {
            let whole_body = req.into_body().collect().await?.to_bytes();
            let data: serde_json::Value = serde_json::from_slice(&whole_body)
                .unwrap_or_else(|_| serde_json::json!({}));

            let session_id = data.get("session_id")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let encrypted_data = data.get("encrypted_data")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            if session_id.is_empty() || encrypted_data.is_empty() {
                return Ok(json_response(ApiResponse::<()> {
                    success: false,
                    data: None,
                    error: Some("缺少参数".into()),
                }));
            }

            // 获取密钥并删除会话（一次性使用）
            let key = match state.session_manager.get_and_remove(session_id) {
                Some(k) => k,
                None => {
                    println!("会话无效或已过期: {}", session_id);
                    return Ok(json_response(ApiResponse::<()> {
                        success: false,
                        data: None,
                        error: Some("会话不存在或已过期".into()),
                    }));
                }
            };

            // 获取密钥的Base64表示（用于demo展示）
            let key_b64 = base64ct::Base64::encode_string(key.as_bytes());

            // 解密登录数据（CTR 模式，与前端 crypto-js 兼容）
            let decrypted = match decrypt_string_ctr(encrypted_data, &key) {
                Ok(data) => data,
                Err(e) => {
                    return Ok(json_response(ApiResponse::<()> {
                        success: false,
                        data: None,
                        error: Some(format!("解密失败: {}", e)),
                    }));
                }
            };

            println!("解密后的登录数据: {}", decrypted);

            // 解析登录数据（格式: username:password）
            let parts: Vec<&str> = decrypted.splitn(2, ':').collect();
            if parts.len() != 2 {
                return Ok(json_response(ApiResponse::<()> {
                    success: false,
                    data: None,
                    error: Some("数据格式错误".into()),
                }));
            }

            let username = parts[0];
            let password = parts[1];

            // 简单验证：用户名必须至少 3 个字符，密码至少 6 个字符
            let valid = username.len() >= 3 && password.len() >= 6;

            if valid {
                println!("登录成功: user={}", username);

                // ⚠️ Demo模式：保存解密详情供展示
                // 生产环境警告：绝对不能在生产环境中保存明文密码！
                let demo_id = uuid::Uuid::new_v4().to_string();
                let demo_result = DemoDecryptResult {
                    key: key_b64,
                    encrypted_data: encrypted_data.to_string(),
                    username: username.to_string(),
                    password: password.to_string(),
                };
                state.demo_results.lock().unwrap().insert(demo_id.clone(), demo_result);

                Ok(json_response(ApiResponse {
                    success: true,
                    data: Some(LoginResponse { demo_id }),
                    error: None,
                }))
            } else {
                Ok(json_response(ApiResponse::<()> {
                    success: false,
                    data: None,
                    error: Some("用户名或密码无效".into()),
                }))
            }
        }

        // ⚠️ Demo专用：获取解密详情
        // 生产环境警告：此接口仅用于demo演示，生产环境绝对不能提供！
        ("GET", "/api/demo/decrypt_result") => {
            let query = req.uri().query().unwrap_or("");
            let demo_id = query
                .split('&')
                .find(|p| p.starts_with("demo_id="))
                .and_then(|p| p.strip_prefix("demo_id="))
                .unwrap_or("");

            if demo_id.is_empty() {
                return Ok(json_response(ApiResponse::<DemoDecryptResponse> {
                    success: false,
                    data: None,
                    error: Some("缺少demo_id参数".into()),
                }));
            }

            let result = state.demo_results.lock().unwrap()
                .get(demo_id)
                .cloned();

            match result {
                Some(data) => {
                    Ok(json_response(ApiResponse {
                        success: true,
                        data: Some(DemoDecryptResponse {
                            key: data.key,
                            encrypted_data: data.encrypted_data,
                            username: data.username,
                            password: data.password,
                        }),
                        error: None,
                    }))
                }
                None => {
                    Ok(json_response(ApiResponse::<DemoDecryptResponse> {
                        success: false,
                        data: None,
                        error: Some("Demo结果不存在或已过期".into()),
                    }))
                }
            }
        }

        // 静态文件
        ("GET", _) => {
            let file_path = match path {
                "/" => "../static/login.html",
                "/success.html" => "../static/success.html",
                _ => "../static/login.html"
            };

            match tokio::fs::read_to_string(file_path).await {
                Ok(content) => {
                    Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header("Content-Type", "text/html; charset=utf-8")
                        .body(Full::new(Bytes::from(content)))
                        .unwrap())
                }
                Err(_) => {
                    Ok(Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .body(Full::new(Bytes::from("404 Not Found")))
                        .unwrap())
                }
            }
        }

        _ => {
            Ok(Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Full::new(Bytes::from("Method Not Allowed")))
                .unwrap())
        }
    }
}

fn json_response<T: serde::Serialize>(data: ApiResponse<T>) -> Response<Full<Bytes>> {
    let json = serde_json::to_string(&data).unwrap();
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .header("Access-Control-Allow-Origin", "*")
        .header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        .header("Access-Control-Allow-Headers", "Content-Type")
        .body(Full::new(Bytes::from(json)))
        .unwrap()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 创建会话管理器（5 分钟超时）
    let session_manager = SessionManager::new(Duration::from_secs(300));

    println!("加密登录示例服务器");
    println!("===================");
    println!("会话管理器已创建（5分钟超时）");
    println!();

    let state = ServerState {
        session_manager: Arc::new(session_manager),
        demo_results: Arc::new(Mutex::new(HashMap::new())),
    };

    let addr: SocketAddr = ([0, 0, 0, 0], 3000).into();
    let listener = TcpListener::bind(addr).await?;
    println!("服务器启动于 http://{}", addr);
    println!("本地浏览器访问: http://127.0.0.1:3000");
    println!("局域网访问: http://<本机IP>:3000");
    println!();

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let state = state.clone();

        tokio::task::spawn(async move {
            let service = service_fn(move |req| handle_request(req, state.clone()));
            if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                eprintln!("连接错误: {}", err);
            }
        });
    }
}
