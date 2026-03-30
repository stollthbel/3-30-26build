use axum::{
    extract::{Path, Query, Request, State},
    http::{header, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use chrono::Utc;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use tower_http::cors::CorsLayer;
use uuid::Uuid;

type Db = Arc<Mutex<Connection>>;

fn secret() -> Vec<u8> {
    std::env::var("JWT_SECRET")
        .unwrap_or_else(|_| "change-me-in-prod".into())
        .into_bytes()
}

// ── Models ─────────────────────────────────────────

#[derive(Clone)]
struct Uid(String);

#[derive(Serialize, Deserialize)]
struct Claims { sub: String, exp: usize }

#[derive(Deserialize)]
struct Auth { email: String, password: String, name: Option<String> }

#[derive(Serialize)]
struct Trade {
    id: String, ticker: String, direction: String,
    entry_price: f64, exit_price: Option<f64>, size: f64,
    entry_time: String, exit_time: Option<String>,
    pnl: Option<f64>, result: Option<String>,
    intent: Option<String>, adherence: Option<i32>,
    violations: Option<String>, followed_plan: bool,
    reflection: Option<String>, emotion: Option<String>,
    setup: Option<String>, created_at: String,
}

#[derive(Deserialize)]
struct NewTrade {
    ticker: String, direction: String,
    entry_price: f64, exit_price: Option<f64>, size: f64,
    entry_time: String, exit_time: Option<String>,
    intent: Option<String>, adherence: Option<i32>,
    violations: Option<Vec<String>>,
    reflection: Option<String>, emotion: Option<String>,
    setup: Option<String>,
}

#[derive(Serialize)]
struct Stats {
    total: usize, wins: usize, losses: usize, win_rate: f64,
    pnl: f64, avg_pnl: f64, profit_factor: f64,
    avg_adherence: f64, streak: i32, max_dd: f64,
}

#[derive(Deserialize)]
struct Filter {
    result: Option<String>, direction: Option<String>,
    ticker: Option<String>, setup: Option<String>,
}

// ── Database ───────────────────────────────────────

fn init(c: &Connection) {
    c.execute_batch("
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL, hash TEXT NOT NULL, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS trades (
            id TEXT PRIMARY KEY, uid TEXT NOT NULL,
            ticker TEXT NOT NULL, direction TEXT NOT NULL,
            entry_price REAL NOT NULL, exit_price REAL, size REAL NOT NULL,
            entry_time TEXT NOT NULL, exit_time TEXT,
            pnl REAL, result TEXT,
            intent TEXT, adherence INTEGER,
            violations TEXT, followed_plan INTEGER NOT NULL DEFAULT 1,
            reflection TEXT, emotion TEXT, setup TEXT,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS rules (
            id TEXT PRIMARY KEY, uid TEXT NOT NULL, rule TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_t ON trades(uid);
        CREATE INDEX IF NOT EXISTS idx_r ON rules(uid);
    ").unwrap();
}

fn row_to_trade(r: &rusqlite::Row) -> rusqlite::Result<Trade> {
    Ok(Trade {
        id: r.get(0)?, ticker: r.get(2)?, direction: r.get(3)?,
        entry_price: r.get(4)?, exit_price: r.get(5)?, size: r.get(6)?,
        entry_time: r.get(7)?, exit_time: r.get(8)?,
        pnl: r.get(9)?, result: r.get(10)?,
        intent: r.get(11)?, adherence: r.get(12)?,
        violations: r.get(13)?,
        followed_plan: r.get::<_, i32>(14).map(|v| v != 0)?,
        reflection: r.get(15)?, emotion: r.get(16)?,
        setup: r.get(17)?, created_at: r.get(18)?,
    })
}

// ── Auth middleware ─────────────────────────────────

async fn auth(mut req: Request, next: Next) -> Result<Response, StatusCode> {
    let tok = req.headers().get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let data = decode::<Claims>(tok, &DecodingKey::from_secret(&secret()), &Validation::default())
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    req.extensions_mut().insert(Uid(data.claims.sub));
    Ok(next.run(req).await)
}

fn token(id: &str) -> String {
    let exp = (Utc::now().timestamp() + 86400 * 30) as usize;
    encode(&Header::default(), &Claims { sub: id.into(), exp },
        &EncodingKey::from_secret(&secret())).unwrap()
}

// ── Handlers ───────────────────────────────────────

async fn signup(State(db): State<Db>, Json(a): Json<Auth>) -> impl IntoResponse {
    let id = Uuid::new_v4().to_string();
    let hash = bcrypt::hash(&a.password, 10).unwrap();
    let name = a.name.unwrap_or_else(|| a.email.split('@').next().unwrap().into());
    let now = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let c = db.lock().unwrap();
    if c.query_row("SELECT count(*) FROM users WHERE email=?", params![a.email], |r| r.get::<_,i32>(0)).unwrap() > 0 {
        return (StatusCode::CONFLICT, Json(serde_json::json!({"error":"Email taken"}))).into_response();
    }
    c.execute("INSERT INTO users VALUES(?1,?2,?3,?4,?5)", params![id,a.email,name,hash,now]).unwrap();
    Json(serde_json::json!({"token":token(&id),"user":{"id":id,"email":a.email,"name":name}})).into_response()
}

async fn login(State(db): State<Db>, Json(a): Json<Auth>) -> impl IntoResponse {
    let c = db.lock().unwrap();
    let u = c.query_row("SELECT id,email,name,hash FROM users WHERE email=?", params![a.email],
        |r| Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?)));
    match u {
        Ok((id,email,name,hash)) if bcrypt::verify(&a.password,&hash).unwrap_or(false) =>
            Json(serde_json::json!({"token":token(&id),"user":{"id":id,"email":email,"name":name}})).into_response(),
        _ => (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error":"Bad credentials"}))).into_response(),
    }
}

async fn me(State(db): State<Db>, axum::Extension(u): axum::Extension<Uid>) -> impl IntoResponse {
    let c = db.lock().unwrap();
    match c.query_row("SELECT id,email,name FROM users WHERE id=?", params![u.0],
        |r| Ok(serde_json::json!({"id":r.get::<_,String>(0)?,"email":r.get::<_,String>(1)?,"name":r.get::<_,String>(2)?}))) {
        Ok(v) => Json(v).into_response(),
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn add_trade(State(db): State<Db>, axum::Extension(u): axum::Extension<Uid>, Json(t): Json<NewTrade>) -> impl IntoResponse {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let (pnl, result) = match t.exit_price {
        Some(ex) => {
            let m = if t.direction == "long" { 1.0 } else { -1.0 };
            let p = m * (ex - t.entry_price) * t.size;
            (Some(p), Some(if p > 0.001 {"win"} else if p < -0.001 {"loss"} else {"breakeven"}))
        }, None => (None, None),
    };
    let vj = t.violations.as_ref().map(|v| serde_json::to_string(v).unwrap());
    let vc = t.violations.as_ref().map(|v| v.len()).unwrap_or(0);
    let fp = t.adherence.unwrap_or(0) >= 4 && vc == 0;
    db.lock().unwrap().execute(
        "INSERT INTO trades VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19)",
        params![id,u.0,t.ticker,t.direction,t.entry_price,t.exit_price,t.size,
            t.entry_time,t.exit_time,pnl,result,t.intent,t.adherence,vj,fp as i32,
            t.reflection,t.emotion,t.setup,now]).unwrap();
    (StatusCode::CREATED, Json(serde_json::json!({"id":id,"pnl":pnl,"result":result})))
}

async fn list_trades(State(db): State<Db>, axum::Extension(u): axum::Extension<Uid>, Query(f): Query<Filter>) -> impl IntoResponse {
    let c = db.lock().unwrap();
    let mut sql = "SELECT * FROM trades WHERE uid=?1".to_string();
    let mut v: Vec<String> = vec![u.0];
    macro_rules! flt { ($f:expr,$col:expr,$op:expr) => {
        if let Some(ref x) = $f { v.push(if $op=="LIKE" {format!("%{x}%")} else {x.clone()});
            sql.push_str(&format!(" AND {} {} ?{}",  $col, $op, v.len())); }
    }}
    flt!(f.result,"result","="); flt!(f.direction,"direction","=");
    flt!(f.ticker,"ticker","LIKE"); flt!(f.setup,"setup","=");
    sql.push_str(" ORDER BY created_at DESC");
    let mut s = c.prepare(&sql).unwrap();
    let p: Vec<&dyn rusqlite::types::ToSql> = v.iter().map(|x| x as &dyn rusqlite::types::ToSql).collect();
    let trades: Vec<Trade> = s.query_map(p.as_slice(), row_to_trade).unwrap().filter_map(|r| r.ok()).collect();
    Json(trades)
}

async fn get_trade(State(db): State<Db>, axum::Extension(u): axum::Extension<Uid>, Path(id): Path<String>) -> impl IntoResponse {
    let c = db.lock().unwrap();
    match c.query_row("SELECT * FROM trades WHERE id=?1 AND uid=?2", params![id,u.0], row_to_trade) {
        Ok(t) => Json(serde_json::to_value(t).unwrap()).into_response(),
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn del_trade(State(db): State<Db>, axum::Extension(u): axum::Extension<Uid>, Path(id): Path<String>) -> StatusCode {
    db.lock().unwrap().execute("DELETE FROM trades WHERE id=?1 AND uid=?2", params![id,u.0]).unwrap();
    StatusCode::NO_CONTENT
}

async fn stats(State(db): State<Db>, axum::Extension(u): axum::Extension<Uid>) -> impl IntoResponse {
    let c = db.lock().unwrap();
    let mut s = c.prepare("SELECT pnl,result,adherence FROM trades WHERE uid=? AND pnl IS NOT NULL ORDER BY created_at ASC").unwrap();
    let rows: Vec<(f64,String,Option<i32>)> = s.query_map(params![u.0], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)))
        .unwrap().filter_map(|r| r.ok()).collect();
    let n = rows.len();
    let w = rows.iter().filter(|r| r.1=="win").count();
    let l = rows.iter().filter(|r| r.1=="loss").count();
    let tp: f64 = rows.iter().map(|r| r.0).sum();
    let gp: f64 = rows.iter().filter(|r| r.0>0.0).map(|r| r.0).sum();
    let gl: f64 = rows.iter().filter(|r| r.0<0.0).map(|r| r.0.abs()).sum();
    let ad: Vec<f64> = rows.iter().filter_map(|r| r.2.map(|a| a as f64)).collect();
    let mut streak: i32 = 0;
    for r in rows.iter().rev() {
        let win = r.1=="win";
        if streak==0 { streak = if win {1} else {-1}; }
        else if (streak>0 && win)||(streak<0 && !win) { streak += if win {1} else {-1}; }
        else { break; }
    }
    let (mut peak, mut cum, mut dd) = (0.0f64, 0.0f64, 0.0f64);
    for r in &rows { cum+=r.0; if cum>peak {peak=cum;} let d=peak-cum; if d>dd {dd=d;} }
    Json(Stats {
        total:n, wins:w, losses:l,
        win_rate: if n>0 {w as f64/n as f64} else {0.0},
        pnl:tp, avg_pnl: if n>0 {tp/n as f64} else {0.0},
        profit_factor: if gl>0.001 {gp/gl} else {0.0},
        avg_adherence: if !ad.is_empty() {ad.iter().sum::<f64>()/ad.len() as f64} else {0.0},
        streak, max_dd:dd,
    })
}

async fn csv(State(db): State<Db>, axum::Extension(u): axum::Extension<Uid>) -> impl IntoResponse {
    let c = db.lock().unwrap();
    let mut s = c.prepare("SELECT * FROM trades WHERE uid=? ORDER BY created_at DESC").unwrap();
    let trades: Vec<Trade> = s.query_map(params![u.0], row_to_trade).unwrap().filter_map(|r| r.ok()).collect();
    let mut out = "Date,Ticker,Direction,Entry,Exit,Size,PnL,Result,Setup,Adherence,Followed,Emotion,Intent,Reflection\n".to_string();
    for t in &trades {
        let esc = |s: &str| if s.contains(',') || s.contains('"') { format!("\"{}\"", s.replace('"',"\"\"")) } else { s.into() };
        out.push_str(&format!("{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
            t.entry_time, t.ticker, t.direction, t.entry_price,
            t.exit_price.map(|v|v.to_string()).unwrap_or_default(), t.size,
            t.pnl.map(|v|format!("{v:.2}")).unwrap_or_default(),
            t.result.as_deref().unwrap_or(""), t.setup.as_deref().unwrap_or(""),
            t.adherence.map(|v|v.to_string()).unwrap_or_default(), t.followed_plan,
            t.emotion.as_deref().unwrap_or(""),
            esc(t.intent.as_deref().unwrap_or("")), esc(t.reflection.as_deref().unwrap_or("")),
        ));
    }
    Response::builder().header("Content-Type","text/csv")
        .header("Content-Disposition","attachment; filename=\"trades.csv\"")
        .body(out).unwrap().into_response()
}

// ── Rules ──────────────────────────────────────────

async fn get_rules(State(db): State<Db>, axum::Extension(u): axum::Extension<Uid>) -> impl IntoResponse {
    let c = db.lock().unwrap();
    let mut s = c.prepare("SELECT id,rule FROM rules WHERE uid=?").unwrap();
    let r: Vec<serde_json::Value> = s.query_map(params![u.0], |r|
        Ok(serde_json::json!({"id":r.get::<_,String>(0)?,"rule":r.get::<_,String>(1)?})))
        .unwrap().filter_map(|r| r.ok()).collect();
    Json(r)
}

#[derive(Deserialize)] struct Rule { rule: String }

async fn add_rule(State(db): State<Db>, axum::Extension(u): axum::Extension<Uid>, Json(r): Json<Rule>) -> impl IntoResponse {
    let id = Uuid::new_v4().to_string();
    db.lock().unwrap().execute("INSERT INTO rules VALUES(?1,?2,?3)", params![id,u.0,r.rule]).unwrap();
    (StatusCode::CREATED, Json(serde_json::json!({"id":id,"rule":r.rule})))
}

async fn del_rule(State(db): State<Db>, axum::Extension(u): axum::Extension<Uid>, Path(id): Path<String>) -> StatusCode {
    db.lock().unwrap().execute("DELETE FROM rules WHERE id=?1 AND uid=?2", params![id,u.0]).unwrap();
    StatusCode::NO_CONTENT
}

// ── Pages ──────────────────────────────────────────

async fn landing() -> Html<&'static str> { Html(include_str!("../static/landing.html")) }
async fn app_page() -> Html<&'static str> { Html(include_str!("../static/app.html")) }

// ── Main ───────────────────────────────────────────

#[tokio::main]
async fn main() {
    std::fs::create_dir_all("data").unwrap();
    let c = Connection::open("data/legacy_edge.db").unwrap();
    init(&c);
    let db: Db = Arc::new(Mutex::new(c));

    let api = Router::new()
        .route("/trades", post(add_trade).get(list_trades))
        .route("/trades/{id}", get(get_trade).delete(del_trade))
        .route("/stats", get(stats))
        .route("/export/csv", get(csv))
        .route("/rules", get(get_rules).post(add_rule))
        .route("/rules/{id}", delete(del_rule))
        .route("/me", get(me))
        .layer(middleware::from_fn(auth));

    let app = Router::new()
        .route("/", get(landing))
        .route("/app", get(app_page))
        .route("/api/signup", post(signup))
        .route("/api/login", post(login))
        .nest("/api", api)
        .layer(CorsLayer::permissive())
        .with_state(db);

    let port = std::env::var("PORT").unwrap_or("3000".into());
    println!("\n  Legacy Edge → http://localhost:{port}\n");
    let l = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}")).await.unwrap();
    axum::serve(l, app).await.unwrap();
}
