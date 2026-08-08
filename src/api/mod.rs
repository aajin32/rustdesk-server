use axum::{
    extract::{ConnectInfo, Extension, Json},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use hbb_common::{anyhow, log, serde_json};
use std::{
    net::{IpAddr, SocketAddr},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
use sqlx::{Row, SqlitePool};

pub const TOKEN_EXPIRE_SECS: i64 = 3 * 24 * 3600;

#[derive(Clone)]
pub struct AppState {
    pub db: SqlitePool,
    pub trusted_proxy: bool,
}

pub async fn open_db(path: &str) -> anyhow::Result<SqlitePool> {
    if !Path::new(path).exists() {
        std::fs::File::create(path)?;
    }
    let url = format!("sqlite://{path}");
    let pool = SqlitePool::connect(&url).await?;
    create_tables(&pool).await?;
    Ok(pool)
}

async fn create_tables(db: &SqlitePool) -> anyhow::Result<()> {
    sqlx::query(
        "create table if not exists users (
            id integer primary key autoincrement,
            username varchar(100) not null unique,
            password_hash varchar(200) not null,
            enabled integer not null default 1,
            created_at integer not null
        );
        create table if not exists sessions (
            token varchar(128) primary key not null,
            user_id integer not null,
            expires_at integer not null,
            login_ip varchar(100) not null,
            created_at integer not null
        );
        create table if not exists ab_data (
            user_id integer primary key not null,
            data text not null,
            updated_at integer not null
        );",
    )
    .execute(db)
    .await?;
    Ok(())
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn normalize_ip(ip: IpAddr, port: u16) -> String {
    hbb_common::try_into_v4(SocketAddr::new(ip, port)).ip().to_string()
}

fn client_ip(headers: &HeaderMap, addr: SocketAddr, trusted_proxy: bool) -> String {
    if trusted_proxy {
        if let Some(ip) = headers
            .get("x-forwarded-for")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.split(',').next().map(|s| s.trim()))
            .and_then(|s| s.parse::<IpAddr>().ok())
        {
            return normalize_ip(ip, 0);
        }
    }
    normalize_ip(addr.ip(), addr.port())
}

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.trim().to_owned())
}

fn json_response(status: StatusCode, body: serde_json::Value) -> Response {
    (status, Json(body)).into_response()
}

fn unauthorized(msg: &str) -> Response {
    json_response(StatusCode::UNAUTHORIZED, serde_json::json!({ "error": msg }))
}

fn user_json(username: &str) -> serde_json::Value {
    serde_json::json!({
        "name": username,
        "display_name": username,
        "avatar": "",
        "status": 1,
        "is_admin": false,
    })
}

pub async fn start_server(port: i32, db_path: &str, trusted_proxy: bool) -> anyhow::Result<()> {
    let db = open_db(db_path).await?;
    let state = AppState { db, trusted_proxy };
    let app = Router::new()
        .route("/api/login", post(login))
        .route("/api/currentUser", post(current_user))
        .route("/api/logout", post(logout))
        .route("/api/login-options", get(login_options))
        .route("/api/ab", get(get_ab).post(post_ab))
        .route("/api/verify-session", post(verify_session))
        .layer(Extension(state));
    let addr = format!("0.0.0.0:{}", port).parse::<SocketAddr>()?;
    log::info!("api-server listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await?;
    Ok(())
}

async fn login(
    Extension(state): Extension<AppState>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    let username = body.get("username").and_then(|v| v.as_str()).unwrap_or("");
    let password = body.get("password").and_then(|v| v.as_str()).unwrap_or("");
    if username.is_empty() || password.is_empty() {
        return unauthorized("用户名或密码为空");
    }
    let result = sqlx::query("select id, password_hash, enabled from users where username = ?")
        .bind(username)
        .fetch_optional(&state.db)
        .await;
    let row = match result {
        Ok(row) => row,
        Err(e) => {
            log::error!("login db error: {e}");
            return json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({ "error": "数据库错误" }),
            );
        }
    };
    let Some(row) = row else {
        return unauthorized("用户名或密码错误");
    };
    let user_id: i64 = row.get("id");
    let password_hash: String = row.get("password_hash");
    let enabled: i64 = row.get("enabled");
    if enabled == 0 || !bcrypt::verify(password, &password_hash).unwrap_or(false) {
        return unauthorized("用户名或密码错误");
    }
    // 登录删旧：只保留最新 session（单点登录）
    let _ = sqlx::query("delete from sessions where user_id = ?")
        .bind(user_id)
        .execute(&state.db)
        .await;
    let token = uuid::Uuid::new_v4().simple().to_string();
    let expires_at = now() + TOKEN_EXPIRE_SECS;
    let login_ip = client_ip(&headers, addr, state.trusted_proxy);
    if let Err(e) = sqlx::query(
        "insert into sessions (token, user_id, expires_at, login_ip, created_at) values (?, ?, ?, ?, ?)",
    )
    .bind(&token)
    .bind(user_id)
    .bind(expires_at)
    .bind(&login_ip)
    .bind(now())
    .execute(&state.db)
    .await
    {
        log::error!("insert session error: {e}");
        return json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({ "error": "数据库错误" }),
        );
    }
    json_response(
        StatusCode::OK,
        serde_json::json!({
            "access_token": token,
            "type": "access_token",
            "user": user_json(username),
            "expires_at": expires_at,
        }),
    )
}

// 返回 (username, user_id)，凭证无效时返回 None
async fn session_user(db: &SqlitePool, token: &str) -> anyhow::Result<Option<(String, i64)>> {
    let row = sqlx::query(
        "select u.id, u.username, u.enabled, s.expires_at from sessions s join users u on s.user_id = u.id where s.token = ?",
    )
    .bind(token)
    .fetch_optional(db)
    .await?;
    let Some(row) = row else { return Ok(None); };
    let expires_at: i64 = row.get("expires_at");
    let enabled: i64 = row.get("enabled");
    if enabled == 0 || expires_at < now() {
        return Ok(None);
    }
    let user_id: i64 = row.get("id");
    let username: String = row.get("username");
    Ok(Some((username, user_id)))
}

async fn current_user(Extension(state): Extension<AppState>, headers: HeaderMap) -> Response {
    let token = match bearer_token(&headers) {
        Some(t) => t,
        None => return unauthorized("缺少凭证"),
    };
    match session_user(&state.db, &token).await {
        Ok(Some((username, _))) => json_response(StatusCode::OK, user_json(&username)),
        Ok(None) => unauthorized("凭证无效"),
        Err(e) => {
            log::error!("current_user db error: {e}");
            json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({ "error": "数据库错误" }),
            )
        }
    }
}

async fn logout(Extension(state): Extension<AppState>, headers: HeaderMap) -> Response {
    let token = match bearer_token(&headers) {
        Some(t) => t,
        None => return unauthorized("缺少凭证"),
    };
    let _ = sqlx::query("delete from sessions where token = ?")
        .bind(&token)
        .execute(&state.db)
        .await;
    StatusCode::OK.into_response()
}

async fn login_options() -> Response {
    json_response(StatusCode::OK, serde_json::json!([]))
}

async fn get_ab(Extension(state): Extension<AppState>, headers: HeaderMap) -> Response {
    let token = match bearer_token(&headers) {
        Some(t) => t,
        None => return unauthorized("缺少凭证"),
    };
    match session_user(&state.db, &token).await {
        Ok(Some((_, user_id))) => {
            let result = sqlx::query("select data from ab_data where user_id = ?")
                .bind(user_id)
                .fetch_optional(&state.db)
                .await;
            match result {
                Ok(Some(row)) => {
                    let data: String = row.get("data");
                    // 契约：data 必须为 JSON 数组（客户端 _deserialize 直接消费）
                    let data = serde_json::from_str::<serde_json::Value>(&data)
                        .unwrap_or_else(|_| serde_json::json!([]));
                    json_response(StatusCode::OK, serde_json::json!({ "data": data }))
                }
                Ok(None) => json_response(StatusCode::OK, serde_json::json!({ "data": [] })),
                Err(e) => {
                    log::error!("get_ab db error: {e}");
                    json_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        serde_json::json!({ "error": "数据库错误" }),
                    )
                }
            }
        }
        Ok(None) => unauthorized("凭证无效"),
        Err(e) => {
            log::error!("get_ab db error: {e}");
            json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({ "error": "数据库错误" }),
            )
        }
    }
}

// 客户端 POST 的 body 为 {"data": [...]}，data 是 JSON 数组
fn parse_ab_data(body: &serde_json::Value) -> Option<String> {
    let data = body.get("data")?;
    if !data.is_array() && !data.is_string() {
        return None;
    }
    serde_json::to_string(data).ok()
}

async fn post_ab(
    Extension(state): Extension<AppState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Response {
    let token = match bearer_token(&headers) {
        Some(t) => t,
        None => return unauthorized("缺少凭证"),
    };
    let Some(data) = parse_ab_data(&body) else {
        return json_response(
            StatusCode::BAD_REQUEST,
            serde_json::json!({ "error": "无效的地址簿数据" }),
        );
    };
    match session_user(&state.db, &token).await {
        Ok(Some((_, user_id))) => {
            let result = sqlx::query(
                "insert into ab_data (user_id, data, updated_at) values (?, ?, ?)
                 on conflict(user_id) do update set data = excluded.data, updated_at = excluded.updated_at",
            )
            .bind(user_id)
            .bind(&data)
            .bind(now())
            .execute(&state.db)
            .await;
            match result {
                Ok(_) => StatusCode::OK.into_response(),
                Err(e) => {
                    log::error!("post_ab db error: {e}");
                    json_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        serde_json::json!({ "error": "数据库错误" }),
                    )
                }
            }
        }
        Ok(None) => unauthorized("凭证无效"),
        Err(e) => {
            log::error!("post_ab db error: {e}");
            json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({ "error": "数据库错误" }),
            )
        }
    }
}

#[derive(serde::Deserialize)]
struct VerifySessionRequest {
    token: String,
    ip: String,
}

// 内网专用：供 hbbs 校验出站许可，无副作用
async fn verify_session(
    Extension(state): Extension<AppState>,
    Json(body): Json<VerifySessionRequest>,
) -> Response {
    let result = sqlx::query(
        "select s.expires_at, s.login_ip, u.enabled from sessions s join users u on s.user_id = u.id where s.token = ?",
    )
    .bind(&body.token)
    .fetch_optional(&state.db)
    .await;
    let row = match result {
        Ok(row) => row,
        Err(e) => {
            log::error!("verify_session db error: {e}");
            return json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({ "error": "数据库错误" }),
            );
        }
    };
    let Some(row) = row else {
        return json_response(
            StatusCode::OK,
            serde_json::json!({ "valid": false, "reason": "not_found" }),
        );
    };
    let enabled: i64 = row.get("enabled");
    let expires_at: i64 = row.get("expires_at");
    let login_ip: String = row.get("login_ip");
    if enabled == 0 {
        return json_response(
            StatusCode::OK,
            serde_json::json!({ "valid": false, "reason": "not_found" }),
        );
    }
    if expires_at < now() {
        return json_response(
            StatusCode::OK,
            serde_json::json!({ "valid": false, "reason": "expired" }),
        );
    }
    // 复核粒度=源 IP：登录时记录的 login_ip 必须与 hbbs 注册源 IP 一致
    if login_ip != body.ip {
        return json_response(
            StatusCode::OK,
            serde_json::json!({ "valid": false, "reason": "ip_mismatch" }),
        );
    }
    json_response(StatusCode::OK, serde_json::json!({ "valid": true }))
}

pub async fn add_user(db: &SqlitePool, username: &str, password: &str) -> anyhow::Result<()> {
    let password_hash = bcrypt::hash(password, bcrypt::DEFAULT_COST)?;
    let result = sqlx::query("insert into users (username, password_hash, enabled, created_at) values (?, ?, 1, ?)")
        .bind(username)
        .bind(&password_hash)
        .bind(now())
        .execute(db)
        .await;
    match result {
        Ok(_) => {
            log::info!("已创建用户 {}", username);
            Ok(())
        }
        Err(e) => {
            if e.to_string().contains("UNIQUE") {
                anyhow::bail!("用户已存在: {}", username);
            }
            Err(e.into())
        }
    }
}

// 改密即失效：改密同时删除该用户全部 session
pub async fn set_password(db: &SqlitePool, username: &str, password: &str) -> anyhow::Result<()> {
    let password_hash = bcrypt::hash(password, bcrypt::DEFAULT_COST)?;
    let result = sqlx::query("update users set password_hash = ? where username = ?")
        .bind(&password_hash)
        .bind(username)
        .execute(db)
        .await?;
    if result.rows_affected() == 0 {
        anyhow::bail!("用户不存在: {}", username);
    }
    let row = sqlx::query("select id from users where username = ?")
        .bind(username)
        .fetch_one(db)
        .await?;
    let user_id: i64 = row.get("id");
    let _ = sqlx::query("delete from sessions where user_id = ?")
        .bind(user_id)
        .execute(db)
        .await;
    log::info!("已修改用户 {} 的密码", username);
    Ok(())
}

pub async fn set_user_enabled(db: &SqlitePool, username: &str, enabled: bool) -> anyhow::Result<()> {
    let enabled_i = if enabled { 1 } else { 0 };
    let result = sqlx::query("update users set enabled = ? where username = ?")
        .bind(enabled_i)
        .bind(username)
        .execute(db)
        .await?;
    if result.rows_affected() == 0 {
        anyhow::bail!("用户不存在: {}", username);
    }
    // 禁用/启用均删除 session，保证立即生效
    let row = sqlx::query("select id from users where username = ?")
        .bind(username)
        .fetch_one(db)
        .await?;
    let user_id: i64 = row.get("id");
    let _ = sqlx::query("delete from sessions where user_id = ?")
        .bind(user_id)
        .execute(db)
        .await;
    log::info!("用户 {} 已{}", username, if enabled { "启用" } else { "禁用" });
    Ok(())
}