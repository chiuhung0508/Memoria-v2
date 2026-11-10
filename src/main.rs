use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use chrono::{Local, Utc};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sqlx::{sqlite::SqlitePoolOptions, Pool, Sqlite};
use std::{
    fs::{self, File, OpenOptions},
    io::{BufReader, Write},
    net::SocketAddr,
    path::{Path as StdPath, PathBuf},
    sync::Arc,
};
use tower_http::services::ServeDir;
use walkdir::WalkDir;

#[derive(Clone)]
struct AppState {
    db: Pool<Sqlite>,
    log_dir: PathBuf,
}

#[derive(Deserialize)]
struct ChangeCredentialsRequest {
    current_username: String,
    current_password: String,
    new_username: String,
    new_password: String,
}

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    token: String,
    username: String,
}

#[derive(Deserialize, Serialize, sqlx::FromRow)]
struct SourceConfigItem {
    id: Option<i64>,
    album_name: String,
    path_location: String,
    tags: Option<String>,
}

#[derive(Deserialize)]
struct MediaFilterQuery {
    date_from: Option<String>,
    date_to: Option<String>,
    album: Option<String>,
    search: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
}

#[derive(Serialize, sqlx::FromRow)]
struct MediaItem {
    id: i64,
    album_name: String,
    file_type: String,
    date_taken: Option<String>,
    latitude: Option<f64>,
    longitude: Option<f64>,
    caption: Option<String>,
    thumb_hash: Option<String>,
}

#[derive(Serialize)]
struct PaginatedResponse {
    total: i64,
    items: Vec<MediaItem>,
}

#[derive(Deserialize)]
struct CaptionUpdateRequest {
    id: i64,
    caption: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let log_dir = PathBuf::from("/data/logs");
    fs::create_dir_all(&log_dir)?;

    let db = SqlitePoolOptions::new()
        .max_connections(10)
        .connect("sqlite:/data/memoria.db?mode=rwc")
        .await?;

    // Enable WAL mode for high concurrency
    sqlx::query("PRAGMA journal_mode = WAL;").execute(&db).await?;
    sqlx::query("PRAGMA synchronous = NORMAL;").execute(&db).await?;

    init_database_schema(&db).await?;

    let state = Arc::new(AppState {
        db: db.clone(),
        log_dir: log_dir.clone(),
    });

    spawn_daily_log_archiver(log_dir.clone());

    let app = Router::new()
        .route("/api/auth/login", post(login_handler))
        .route("/api/auth/change-credentials", post(change_credentials_handler))
        .route("/api/config", get(get_configs).post(save_configs_handler))
        .route("/api/sync", post(trigger_sync_handler))
        .route("/api/media", get(list_media_handler))
        .route("/api/media/albums", get(list_albums_handler))
        .route("/api/media/caption", post(update_caption_handler))
        .route("/api/stream/file/:id", get(stream_media_file))
        .fallback_service(ServeDir::new("dist"))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    println!("Memoria Backend listening at http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn init_database_schema(db: &Pool<Sqlite>) -> Result<(), Box<dyn std::error::Error>> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS sources_config (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            album_name TEXT NOT NULL,
            path_location TEXT NOT NULL UNIQUE,
            tags TEXT,
            last_synced DATETIME
        );
        CREATE TABLE IF NOT EXISTS media (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_id INTEGER REFERENCES sources_config(id) ON DELETE CASCADE,
            album_name TEXT,
            file_path TEXT NOT NULL UNIQUE,
            file_type TEXT NOT NULL,
            date_taken TEXT,
            latitude REAL,
            longitude REAL,
            caption TEXT DEFAULT '',
            thumb_hash TEXT,
            tags TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_media_date ON media(date_taken);
        CREATE INDEX IF NOT EXISTS idx_media_album ON media(album_name);
        "#
    ).execute(db).await?;

    // Seed default demo:demo account if not present
    let exists: Option<i64> = sqlx::query_scalar("SELECT id FROM users WHERE username = 'demo'")
        .fetch_optional(db)
        .await?;

    if exists.is_none() {
        sqlx::query("INSERT INTO users (username, password_hash) VALUES ('demo', 'demo')")
            .execute(db)
            .await?;
    }
    Ok(())
}

async fn login_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, (StatusCode, Json<serde_json::Value>)> {
    let u = payload.username.trim();
    let p = payload.password;
    let user: Option<String> = sqlx::query_scalar(
        "SELECT username FROM users WHERE username = ? AND password_hash = ?"
    )
    .bind(u)
    .bind(&p)
    .fetch_optional(&state.db)
    .await
    .unwrap_or(None);

    if let Some(username) = user {
        return Ok(Json(LoginResponse {
            token: "demo-session-token".to_string(),
            username,
        }));
    }
    Err((
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({ "error": "Invalid username or password" })),
    ))
}

async fn change_credentials_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ChangeCredentialsRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let curr_user = payload.current_username.trim();
    let curr_pass = &payload.current_password;
    let new_user = payload.new_username.trim();
    let new_pass = &payload.new_password;

    if new_user.is_empty() || new_pass.len() < 4 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "New username and password (min 4 characters) are required." })),
        ));
    }

    let user_id: Option<i64> = sqlx::query_scalar(
        "SELECT id FROM users WHERE username = ? AND password_hash = ?"
    )
    .bind(curr_user)
    .bind(curr_pass)
    .fetch_optional(&state.db)
    .await
    .unwrap_or(None);

    let Some(uid) = user_id else {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "Current password is incorrect." })),
        ));
    };

    let existing: Option<i64> = sqlx::query_scalar(
        "SELECT id FROM users WHERE username = ? AND id != ?"
    )
    .bind(new_user)
    .bind(uid)
    .fetch_optional(&state.db)
    .await
    .unwrap_or(None);

    if existing.is_some() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": format!("Username {} is already in use.", new_user) })),
        ));
    }

    let _ = sqlx::query("UPDATE users SET username = ?, password_hash = ? WHERE id = ?")
        .bind(new_user)
        .bind(new_pass)
        .bind(uid)
        .execute(&state.db)
        .await;

    Ok(Json(serde_json::json!({
        "status": "ok",
        "username": new_user,
        "message": "Credentials updated successfully."
    })))
}

async fn get_configs(State(state): State<Arc<AppState>>) -> Result<Json<Vec<SourceConfigItem>>, StatusCode> {
    let items = sqlx::query_as::<_, SourceConfigItem>(
        "SELECT id, album_name, path_location, tags FROM sources_config"
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();
    Ok(Json(items))
}

async fn save_configs_handler(
    State(state): State<Arc<AppState>>,
    Json(configs): Json<Vec<SourceConfigItem>>,
) -> Result<StatusCode, StatusCode> {
    for cfg in configs {
        let _ = sqlx::query(
            r#"
            INSERT INTO sources_config (album_name, path_location, tags)
            VALUES (?, ?, ?)
            ON CONFLICT(path_location) DO UPDATE SET
                album_name = excluded.album_name,
                tags = excluded.tags
            "#
        )
        .bind(&cfg.album_name)
        .bind(&cfg.path_location)
        .bind(&cfg.tags)
        .execute(&state.db)
        .await;
    }
    Ok(StatusCode::OK)
}

async fn trigger_sync_handler(State(state): State<Arc<AppState>>) -> Result<StatusCode, StatusCode> {
    let db = state.db.clone();
    tokio::spawn(async move {
        let sources = sqlx::query_as::<_, SourceConfigItem>(
            "SELECT id, album_name, path_location, tags FROM sources_config"
        )
        .fetch_all(&db)
        .await
        .unwrap_or_default();

        for src in sources {
            let path = PathBuf::from(&src.path_location);
            if !path.exists() { continue; }

            for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()).filter(|e| e.file_type().is_file()) {
                let f_path = entry.path().to_string_lossy().to_string();
                let ext = entry.path().extension().and_then(|s| s.to_str()).unwrap_or("").to_lowercase();
                let is_img = ["jpg", "jpeg", "png", "webp"].contains(&ext.as_str());
                let is_vid = ["mp4", "mov", "mkv", "webm"].contains(&ext.as_str());

                if !is_img && !is_vid { continue; }
                let file_type = if is_img { "image" } else { "video" };

                let _ = sqlx::query(
                    r#"
                    INSERT INTO media (source_id, album_name, file_path, file_type, date_taken)
                    VALUES (?, ?, ?, ?, datetime('now'))
                    ON CONFLICT(file_path) DO NOTHING
                    "#
                )
                .bind(src.id)
                .bind(&src.album_name)
                .bind(&f_path)
                .bind(file_type)
                .execute(&db)
                .await;
            }
        }
    });
    Ok(StatusCode::ACCEPTED)
}

async fn list_albums_handler(State(state): State<Arc<AppState>>) -> Result<Json<Vec<String>>, StatusCode> {
    let albums: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT album_name FROM media WHERE album_name IS NOT NULL ORDER BY album_name ASC"
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    Ok(Json(albums))
}

async fn list_media_handler(
    State(state): State<Arc<AppState>>,
    Query(filter): Query<MediaFilterQuery>,
) -> Result<Json<PaginatedResponse>, StatusCode> {
    let limit = filter.limit.unwrap_or(40);
    let offset = filter.offset.unwrap_or(0);

    let mut where_clause = " WHERE 1=1".to_string();
    if filter.search.is_some() {
        where_clause.push_str(" AND (caption LIKE ? OR album_name LIKE ?)");
    } else {
        if filter.date_from.is_some() { where_clause.push_str(" AND date_taken >= ?"); }
        if filter.date_to.is_some() { where_clause.push_str(" AND date_taken <= ?"); }
        if filter.album.is_some() { where_clause.push_str(" AND album_name = ?"); }
    }

    let count_query = format!("SELECT COUNT(*) FROM media {}", where_clause);
    let mut q_count = sqlx::query_scalar::<_, i64>(&count_query);
    if let Some(ref s) = filter.search {
        let pattern = format!("%{}%", s);
        q_count = q_count.bind(pattern.clone()).bind(pattern);
    } else {
        if let Some(ref f) = filter.date_from { q_count = q_count.bind(f); }
        if let Some(ref t) = filter.date_to { q_count = q_count.bind(t); }
        if let Some(ref a) = filter.album { q_count = q_count.bind(a); }
    }

    let total = q_count.fetch_one(&state.db).await.unwrap_or(0);

    let select_query = format!(
        "SELECT id, album_name, file_type, date_taken, latitude, longitude, caption, thumb_hash FROM media {} ORDER BY date_taken DESC LIMIT ? OFFSET ?",
        where_clause
    );

    let mut q_items = sqlx::query_as::<_, MediaItem>(&select_query);
    if let Some(ref s) = filter.search {
        let pattern = format!("%{}%", s);
        q_items = q_items.bind(pattern.clone()).bind(pattern);
    } else {
        if let Some(ref f) = filter.date_from { q_items = q_items.bind(f); }
        if let Some(ref t) = filter.date_to { q_items = q_items.bind(t); }
        if let Some(ref a) = filter.album { q_items = q_items.bind(a); }
    }
    q_items = q_items.bind(limit).bind(offset);

    let items = q_items.fetch_all(&state.db).await.unwrap_or_default();
    Ok(Json(PaginatedResponse { total, items }))
}

async fn update_caption_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<CaptionUpdateRequest>,
) -> Result<StatusCode, StatusCode> {
    sqlx::query("UPDATE media SET caption = ? WHERE id = ?")
        .bind(&payload.caption)
        .bind(payload.id)
        .execute(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(StatusCode::OK)
}

async fn stream_media_file(
    Path(id): Path<i64>,
    State(state): State<Arc<AppState>>,
    req: axum::extract::Request,
) -> Result<Response, StatusCode> {
    let path_str: String = sqlx::query_scalar("SELECT file_path FROM media WHERE id = ?")
        .bind(id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;

    let service = tower_http::services::ServeFile::new(path_str);
    tower_http::services::fs::ServeFileSystemResponseBody::into_response(
        tower::Service::call(&mut service.clone(), req)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
    )
}

fn spawn_daily_log_archiver(log_dir: PathBuf) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await;
            let yesterday = (Local::now() - chrono::Duration::days(1)).format("%Y-%m-%d").to_string();
            let log_file_name = format!("memoria-{}.log", yesterday);
            let zip_file_name = format!("memoria-{}.zip", yesterday);

            let log_path = log_dir.join(&log_file_name);
            let zip_path = log_dir.join(&zip_file_name);

            if log_path.exists() && !zip_path.exists() {
                if let (Ok(src_file), Ok(zip_file)) = (File::open(&log_path), File::create(&zip_path)) {
                    let mut zip = zip::ZipWriter::new(zip_file);
                    let options = zip::write::SimpleFileOptions::default()
                        .compression_method(zip::CompressionMethod::Deflated);

                    if zip.start_file(&log_file_name, options).is_ok() {
                        let mut reader = BufReader::new(src_file);
                        let _ = std::io::copy(&mut reader, &mut zip);
                        let _ = zip.finish();
                        let _ = fs::remove_file(log_path);
                    }
                }
            }
        }
    });
}
