#!/usr/bin/env python3
import http.server
import socketserver
import socket
import subprocess
import json
import sqlite3
import os
import secrets
import urllib.parse
from datetime import datetime

HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", 8080))
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DB_PATH", os.path.join(BASE_DIR, "data", "memoria.db"))
DIST_DIR = os.path.join(BASE_DIR, "dist")
SOURCES_DIR = os.path.join(BASE_DIR, "media_sources")


def get_local_network_urls():
    urls = [f"http://localhost:{PORT}", f"http://127.0.0.1:{PORT}"]
    extra_urls = os.environ.get("HOST_NETWORK_URLS", "http://memoria-demo.local:8080,http://192.168.1.100:8080")
    if extra_urls:
        for u in extra_urls.split(","):
            u = u.strip()
            if u and u not in urls:
                urls.append(u)
    if os.environ.get("AUTO_DETECT_LAN", "0") == "1":
        try:
            hostname = socket.gethostname()
            if hostname:
                url = f"http://{hostname}.local:{PORT}"
                if url not in urls:
                    urls.append(url)
        except Exception:
            pass
        try:
            out = subprocess.check_output(["hostname", "-I"], text=True).strip()
            for ip in out.split():
                if ":" not in ip:
                    url = f"http://{ip}:{PORT}"
                    if url not in urls:
                        urls.append(url)
        except Exception:
            pass
    return urls


def resolve_source_path(raw_path):
    if not raw_path:
        return ""
    p = raw_path.strip()
    if os.path.exists(p):
        return p
    for prefix in ("/app/media_sources", "/media_sources", "media_sources"):
        if p == prefix or p.startswith(prefix + "/"):
            sub = p[len(prefix):].lstrip("/")
            candidate = os.path.join(SOURCES_DIR, sub) if sub else SOURCES_DIR
            if os.path.exists(candidate):
                return candidate
    return p


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = get_db()
    c = conn.cursor()
    c.execute("PRAGMA journal_mode = WAL;")
    c.execute("PRAGMA synchronous = NORMAL;")
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    """)

    # Migrate sources_config if it had UNIQUE on path_location so multiple albums can be configured freely
    src_schema = c.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='sources_config'").fetchone()
    if src_schema and "path_location TEXT NOT NULL UNIQUE" in (src_schema[0] or ""):
        c.execute("ALTER TABLE sources_config RENAME TO sources_config_old;")
        c.execute("""
            CREATE TABLE sources_config (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                album_name TEXT NOT NULL,
                path_location TEXT NOT NULL,
                tags TEXT,
                last_synced DATETIME
            );
        """)
        c.execute("""
            INSERT INTO sources_config (id, album_name, path_location, tags, last_synced)
            SELECT id, album_name, path_location, tags, last_synced FROM sources_config_old;
        """)
        c.execute("DROP TABLE sources_config_old;")
    else:
        c.execute("""
            CREATE TABLE IF NOT EXISTS sources_config (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                album_name TEXT NOT NULL,
                path_location TEXT NOT NULL,
                tags TEXT,
                last_synced DATETIME
            );
        """)

    # Migrate media table if file_path had single-column UNIQUE instead of UNIQUE(album_name, file_path)
    media_schema = c.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='media'").fetchone()
    if media_schema and "file_path TEXT NOT NULL UNIQUE" in (media_schema[0] or ""):
        c.execute("ALTER TABLE media RENAME TO media_old;")
        c.execute("""
            CREATE TABLE media (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_id INTEGER REFERENCES sources_config(id) ON DELETE CASCADE,
                album_name TEXT,
                file_path TEXT NOT NULL,
                file_type TEXT NOT NULL,
                date_taken TEXT,
                latitude REAL,
                longitude REAL,
                caption TEXT DEFAULT "",
                thumb_hash TEXT,
                tags TEXT,
                UNIQUE(album_name, file_path)
            );
        """)
        c.execute("""
            INSERT OR IGNORE INTO media (id, source_id, album_name, file_path, file_type, date_taken, latitude, longitude, caption, thumb_hash, tags)
            SELECT id, source_id, album_name, file_path, file_type, date_taken, latitude, longitude, caption, thumb_hash, tags FROM media_old;
        """)
        c.execute("DROP TABLE media_old;")
    else:
        c.execute("""
            CREATE TABLE IF NOT EXISTS media (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_id INTEGER REFERENCES sources_config(id) ON DELETE CASCADE,
                album_name TEXT,
                file_path TEXT NOT NULL,
                file_type TEXT NOT NULL,
                date_taken TEXT,
                latitude REAL,
                longitude REAL,
                caption TEXT DEFAULT "",
                thumb_hash TEXT,
                tags TEXT,
                UNIQUE(album_name, file_path)
            );
        """)

    # Virtual albums & linked items (links only to existing media table records)
    c.execute("""
        CREATE TABLE IF NOT EXISTS virtual_albums (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            album_name TEXT NOT NULL UNIQUE,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS virtual_album_items (
            album_name TEXT NOT NULL,
            media_id INTEGER NOT NULL REFERENCES media(id) ON DELETE CASCADE,
            added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (album_name, media_id)
        );
    """)

    # Secured shared virtual albums with 4-digit passcode
    c.execute("""
        CREATE TABLE IF NOT EXISTS sharing_albums (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            share_token TEXT NOT NULL UNIQUE,
            passcode TEXT NOT NULL,
            album_name TEXT NOT NULL,
            media_ids TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    """)

    c.execute("CREATE INDEX IF NOT EXISTS idx_media_date ON media(date_taken);")
    c.execute("CREATE INDEX IF NOT EXISTS idx_media_album ON media(album_name);")

    # Insert default demo user if not exists
    c.execute("DELETE FROM users WHERE username = 'admin' AND password_hash = 'admin'")
    c.execute("INSERT OR IGNORE INTO users (username, password_hash) VALUES (?, ?)", ("demo", "demo"))

    # Seed default sources & sample photographs only when database is empty
    existing_sources = c.execute("SELECT COUNT(*) FROM sources_config").fetchone()[0]
    existing_media = c.execute("SELECT COUNT(*) FROM media").fetchone()[0]

    if existing_sources == 0:
        default_sources = [
            ("Nature & Wilderness", os.path.join(SOURCES_DIR, "nature"), "mountains,lake,waterfall,forest"),
            ("European Summer Tour", os.path.join(SOURCES_DIR, "cities"), "europe,paris,prague,architecture"),
            ("California Road Trip", os.path.join(SOURCES_DIR, "california"), "coast,pacific,highway1,sunset"),
            ("Travel to Japan 2025", os.path.join(SOURCES_DIR, "japan"), "tokyo,shibuya,temple,garden")
        ]
        for album, path, tags in default_sources:
            c.execute("INSERT INTO sources_config (album_name, path_location, tags, last_synced) VALUES (?, ?, ?, datetime('now'))", (album, path, tags))

    if existing_media == 0:
        src_map = {r["album_name"]: r["id"] for r in c.execute("SELECT id, album_name FROM sources_config").fetchall()}
        samples = [
            ("nature/mountain_lake.jpg", "Nature & Wilderness", "2025-06-18 10:24:00", 46.5197, 8.4412, "Pristine emerald lake surrounded by majestic snow-capped alpine peaks."),
            ("nature/waterfall_cascade.jpg", "Nature & Wilderness", "2025-06-20 14:15:30", 45.4215, -121.8947, "Lush mossy waterfall cascading through the Pacific temperate rainforest."),
            ("nature/pine_forest.jpg", "Nature & Wilderness", "2025-06-22 08:45:10", None, None, "Misty morning sunbeams filtering through dense cedar and pine branches (No GPS)."),
            ("nature/wilderness_peaks.jpg", "Nature & Wilderness", "2025-07-02 16:30:00", 44.4280, -110.5885, "Sweeping vistas over sprawling national park valleys and rugged crests."),
            ("cities/european_avenue.jpg", "European Summer Tour", "2025-07-14 11:10:00", 48.8566, 2.3522, "Classic Haussmannian architecture along tree-lined Parisian avenues."),
            ("cities/morning_cafe.jpg", "European Summer Tour", "2025-07-15 09:20:00", None, None, "Enjoying a morning espresso and warm croissants on a quaint cobblestone street (No GPS)."),
            ("cities/historic_bridge.jpg", "European Summer Tour", "2025-07-18 19:50:00", 50.0878, 14.4205, "Gothic statues standing sentinel over historic river waters at dusk."),
            ("california/pacific_coastline.jpg", "California Road Trip", "2025-08-05 17:40:00", 36.3168, -121.8885, "Waves crashing against dramatic ocean sea stacks along Route 1 at Big Sur."),
            ("california/sunset_pier.jpg", "California Road Trip", "2025-08-08 20:05:00", 34.0100, -118.4962, "Golden hour reflections dancing across gentle Pacific tide ripples."),
            ("california/coastal_coffee.jpg", "California Road Trip", "2025-08-10 10:00:00", None, None, "Freshly brewed single-origin pour-over overlooking the ocean breeze (No GPS)."),
            ("japan/shibuya_crossing.jpg", "Travel to Japan 2025", "2025-10-12 21:15:00", 35.6595, 139.7005, "Dynamic currents of city life under dazzling neon facades in Shibuya."),
            ("japan/shrine_garden.jpg", "Travel to Japan 2025", "2025-10-15 14:00:00", None, None, "Peaceful maple leaves sheltering moss stones beside a wooden engawa veranda (No GPS).")
        ]
        for rel_path, album, dt, lat, lon, caption in samples:
            abs_path = os.path.join(SOURCES_DIR, rel_path)
            c.execute("""
                INSERT OR IGNORE INTO media (source_id, album_name, file_path, file_type, date_taken, latitude, longitude, caption)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (src_map.get(album), album, abs_path, "image", dt, lat, lon, caption))
    else:
        # Ensure existing media rows have source_id linked where album_name matches
        c.execute("""
            UPDATE media
            SET source_id = (SELECT id FROM sources_config WHERE sources_config.album_name = media.album_name LIMIT 1)
            WHERE source_id IS NULL
        """)

    conn.commit()
    conn.close()


def sync_all_sources(conn):
    sources = conn.execute("SELECT id, album_name, path_location FROM sources_config").fetchall()
    added_count = 0
    for src in sources:
        resolved_p = resolve_source_path(src["path_location"])
        if resolved_p and os.path.exists(resolved_p):
            for root, _, files in os.walk(resolved_p):
                for f in sorted(files):
                    if f.lower().endswith((".jpg", ".jpeg", ".png", ".webp")):
                        full_p = os.path.join(root, f)
                        # Check if another media row already has metadata (date_taken, lat, lon, caption) for this file
                        existing_meta = conn.execute(
                            "SELECT date_taken, latitude, longitude, caption FROM media WHERE file_path = ? LIMIT 1",
                            (full_p,)
                        ).fetchone()
                        dt = existing_meta["date_taken"] if existing_meta and existing_meta["date_taken"] else datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        lat = existing_meta["latitude"] if existing_meta else None
                        lon = existing_meta["longitude"] if existing_meta else None
                        cap = existing_meta["caption"] if existing_meta and existing_meta["caption"] else ""
                        cur = conn.execute("""
                            INSERT OR IGNORE INTO media (source_id, album_name, file_path, file_type, date_taken, latitude, longitude, caption)
                            VALUES (?, ?, ?, 'image', ?, ?, ?, ?)
                        """, (src["id"], src["album_name"], full_p, dt, lat, lon, cap))
                        if cur.rowcount > 0:
                            added_count += 1
        conn.execute("UPDATE sources_config SET last_synced = datetime('now') WHERE id = ?", (src["id"],))
    conn.commit()
    return added_count


def get_all_albums_summary(conn):
    album_dict = {}

    # 1. Configured physical/SMB sources from sources_config
    for r in conn.execute("SELECT id, album_name, path_location, last_synced FROM sources_config ORDER BY album_name ASC").fetchall():
        name = (r["album_name"] or "").strip()
        if not name:
            continue
        album_dict[name] = {
            "album_name": name,
            "min_date": "",
            "max_date": "",
            "count": 0,
            "is_virtual": False,
            "source_id": r["id"]
        }

    # 2. Virtual albums from virtual_albums
    for r in conn.execute("SELECT id, album_name, created_at FROM virtual_albums ORDER BY album_name ASC").fetchall():
        name = (r["album_name"] or "").strip()
        if not name:
            continue
        if name not in album_dict:
            album_dict[name] = {
                "album_name": name,
                "min_date": r["created_at"] or "",
                "max_date": r["created_at"] or "",
                "count": 0,
                "is_virtual": True,
                "source_id": None
            }
        else:
            album_dict[name]["is_virtual"] = True

    # 3. Direct media statistics
    media_rows = conn.execute("""
        SELECT album_name, MIN(date_taken) AS min_date, MAX(date_taken) AS max_date, COUNT(*) AS item_count
        FROM media
        WHERE album_name IS NOT NULL AND TRIM(album_name) != ''
        GROUP BY album_name
    """).fetchall()
    for r in media_rows:
        name = r["album_name"].strip()
        if name not in album_dict:
            album_dict[name] = {
                "album_name": name,
                "min_date": r["min_date"] or "",
                "max_date": r["max_date"] or "",
                "count": r["item_count"] or 0,
                "is_virtual": False,
                "source_id": None
            }
        else:
            album_dict[name]["min_date"] = r["min_date"] or album_dict[name]["min_date"]
            album_dict[name]["max_date"] = r["max_date"] or album_dict[name]["max_date"]
            album_dict[name]["count"] = r["item_count"] or 0

    # 4. Virtual album linked items statistics
    virt_rows = conn.execute("""
        SELECT vai.album_name,
               MIN(m.date_taken) AS min_date,
               MAX(m.date_taken) AS max_date,
               COUNT(DISTINCT m.id) AS item_count
        FROM virtual_album_items vai
        JOIN media m ON m.id = vai.media_id
        GROUP BY vai.album_name
    """).fetchall()
    for r in virt_rows:
        name = r["album_name"].strip()
        if name not in album_dict:
            album_dict[name] = {
                "album_name": name,
                "min_date": r["min_date"] or "",
                "max_date": r["max_date"] or "",
                "count": r["item_count"] or 0,
                "is_virtual": True,
                "source_id": None
            }
        else:
            # Combine counts/dates if virtual album has linked items
            total_distinct = conn.execute("""
                SELECT COUNT(DISTINCT id), MIN(date_taken), MAX(date_taken)
                FROM media
                WHERE album_name = ? OR id IN (SELECT media_id FROM virtual_album_items WHERE album_name = ?)
            """, (name, name)).fetchone()
            album_dict[name]["count"] = total_distinct[0] or 0
            if total_distinct[1]:
                album_dict[name]["min_date"] = total_distinct[1]
            if total_distinct[2]:
                album_dict[name]["max_date"] = total_distinct[2]

    albums = sorted(album_dict.values(), key=lambda x: x["album_name"].lower())
    return albums


class MediaVaultHandler(http.server.SimpleHTTPRequestHandler):
    def send_json(self, data, status=200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        if self.path == "/favicon.ico":
            self.send_response(204)
            self.end_headers()
            return

        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        # Serve static assets from DIST_DIR
        rel_file = path.lstrip("/")
        if rel_file == "" or rel_file == "index.html":
            rel_file = "index.html"
        static_target = os.path.join(DIST_DIR, rel_file)
        if os.path.exists(static_target) and os.path.isfile(static_target):
            mime = "text/html; charset=utf-8"
            if static_target.endswith(".css"):
                mime = "text/css"
            elif static_target.endswith((".js", ".mjs")):
                mime = "application/javascript"
            elif static_target.endswith((".json", ".geojson")):
                mime = "application/json"
            elif static_target.endswith((".png", ".jpg", ".jpeg", ".webp")):
                mime = "image/" + static_target.split(".")[-1]
            with open(static_target, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            self.wfile.write(content)
            return

        elif path == "/api/media/albums":
            conn = get_db()
            albums = get_all_albums_summary(conn)
            conn.close()
            self.send_json(albums)
            return

        elif path == "/api/media":
            limit = int(query.get("limit", [40])[0])
            offset = int(query.get("offset", [0])[0])
            search = query.get("search", [None])[0]
            date_from = query.get("date_from", [None])[0]
            date_to = query.get("date_to", [None])[0]
            album = query.get("album", [None])[0]
            sort = query.get("sort", ["date_desc"])[0]

            order_map = {
                "date_asc": "date_taken ASC, id ASC",
                "date_desc": "date_taken DESC, id DESC",
                "name_asc": "album_name ASC, file_path ASC",
                "name_desc": "album_name DESC, file_path DESC"
            }
            order_sql = order_map.get(sort, "date_taken DESC, id DESC")

            conn = get_db()
            where = ["1=1"]
            params = []

            if search:
                where.append("(caption LIKE ? OR album_name LIKE ?)")
                params.extend([f"%{search}%", f"%{search}%"])
            if date_from:
                where.append("date_taken >= ?")
                params.append(date_from)
            if date_to:
                where.append("date_taken <= ?")
                params.append(date_to)
            if album:
                where.append("(album_name = ? OR id IN (SELECT media_id FROM virtual_album_items WHERE album_name = ?))")
                params.extend([album, album])

            where_sql = " AND ".join(where)
            total = conn.execute(f"SELECT COUNT(*) FROM media WHERE {where_sql}", params).fetchone()[0]

            query_sql = f"SELECT id, album_name, file_type, date_taken, latitude, longitude, caption, thumb_hash FROM media WHERE {where_sql} ORDER BY {order_sql} LIMIT ? OFFSET ?"
            rows = conn.execute(query_sql, params + [limit, offset]).fetchall()

            items = []
            for r in rows:
                items.append({
                    "id": r["id"],
                    "album_name": album if album else r["album_name"],
                    "origin_album": r["album_name"],
                    "file_type": r["file_type"],
                    "date_taken": r["date_taken"],
                    "latitude": r["latitude"],
                    "longitude": r["longitude"],
                    "caption": r["caption"],
                    "thumb_hash": r["thumb_hash"]
                })
            conn.close()
            self.send_json({"total": total, "items": items})
            return

        elif path.startswith("/api/stream/file/"):
            media_id = path.split("/")[-1]
            conn = get_db()
            row = conn.execute("SELECT file_path, file_type FROM media WHERE id = ?", (media_id,)).fetchone()
            conn.close()
            if not row:
                self.send_error(404, "Media not found")
                return

            fpath = row["file_path"]
            if not os.path.exists(fpath):
                fpath = resolve_source_path(fpath)
            if os.path.exists(fpath):
                mime = "image/jpeg" if fpath.endswith((".jpg", ".jpeg")) else "image/png"
                with open(fpath, "rb") as f:
                    content = f.read()
                self.send_response(200)
                self.send_header("Content-Type", mime)
                self.send_header("Content-Length", str(len(content)))
                self.send_header("Cache-Control", "public, max-age=86400")
                self.end_headers()
                self.wfile.write(content)
                return
            else:
                self.send_error(404, "File missing on disk")
                return

        elif path == "/api/config":
            conn = get_db()
            rows = conn.execute("SELECT id, album_name, path_location, tags, last_synced FROM sources_config ORDER BY id ASC").fetchall()
            items = [
                {
                    "id": r["id"],
                    "album_name": r["album_name"],
                    "path_location": r["path_location"],
                    "tags": r["tags"],
                    "last_synced": r["last_synced"]
                }
                for r in rows
            ]
            conn.close()
            self.send_json(items)
            return

        elif path == "/api/share/info":
            token = query.get("token", [""])[0].strip()
            conn = get_db()
            row = conn.execute(
                "SELECT share_token, album_name, media_ids, created_at FROM sharing_albums WHERE share_token = ?",
                (token,)
            ).fetchone()
            conn.close()
            if not row:
                self.send_json({"exists": False, "error": "Shared album link not found or expired."}, status=404)
                return
            try:
                mids = json.loads(row["media_ids"] or "[]")
            except Exception:
                mids = []
            self.send_json({
                "exists": True,
                "share_token": row["share_token"],
                "album_name": row["album_name"],
                "media_count": len(mids),
                "created_at": row["created_at"],
                "requires_passcode": True
            })
            return

        elif path == "/api/share/list":
            conn = get_db()
            rows = conn.execute(
                "SELECT id, share_token, passcode, album_name, media_ids, created_at FROM sharing_albums ORDER BY id DESC"
            ).fetchall()
            conn.close()
            items = []
            for r in rows:
                try:
                    mids = json.loads(r["media_ids"] or "[]")
                except Exception:
                    mids = []
                items.append({
                    "id": r["id"],
                    "share_token": r["share_token"],
                    "passcode": r["passcode"],
                    "album_name": r["album_name"],
                    "media_count": len(mids),
                    "created_at": r["created_at"],
                    "share_url": f"/?share={r['share_token']}"
                })
            self.send_json(items)
            return

        elif path == "/api/network":
            self.send_json({"host": HOST, "port": PORT, "urls": get_local_network_urls()})
            return

        elif path == "/admin" or path == "/api/status":
            conn = get_db()
            media_count = conn.execute("SELECT COUNT(*) FROM media").fetchone()[0]
            sources_count = conn.execute("SELECT COUNT(*) FROM sources_config").fetchone()[0]
            albums = get_all_albums_summary(conn)
            conn.close()
            net_urls = get_local_network_urls()
            net_badges = "".join([f'<a href="{u}" class="px-2.5 py-1 bg-zinc-950 border border-zinc-800 hover:border-blue-500 rounded text-xs font-mono text-blue-400">{u}</a>' for u in net_urls])

            html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Memoria - Backend Diagnostics</title>
  <link rel="stylesheet" href="/vendor/tailwind.css" />
  <style>
    body {{ background-color: #09090b; color: #f4f4f5; font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }}
    .card {{ background-color: #18181b; border: 1px solid #27272a; border-radius: 12px; padding: 20px; }}
  </style>
</head>
<body class="bg-zinc-950 text-zinc-100 min-h-screen p-8">
  <div class="max-w-4xl mx-auto space-y-6">
    <div class="flex items-center justify-between border-b border-zinc-800 pb-4">
      <div>
        <h1 class="text-2xl font-bold flex items-center gap-2">
          <span class="text-blue-500">🛡️</span> Memoria Backend Service
        </h1>
        <p class="text-xs text-zinc-400 mt-1">Status: Active & Operational (SQLite WAL Mode)</p>
      </div>
      <a href="/" class="px-3 py-1.5 text-xs bg-blue-600 hover:bg-blue-500 text-white rounded font-medium">Open Frontend Viewer &rarr;</a>
    </div>

    <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
      <div class="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
        <div class="text-xs text-zinc-400 uppercase font-semibold">Indexed Media Files</div>
        <div class="text-3xl font-bold text-emerald-400 mt-1">{media_count}</div>
      </div>
      <div class="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
        <div class="text-xs text-zinc-400 uppercase font-semibold">Configured Sources</div>
        <div class="text-3xl font-bold text-blue-400 mt-1">{sources_count}</div>
      </div>
      <div class="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
        <div class="text-xs text-zinc-400 uppercase font-semibold">Total Albums (Source & Virtual)</div>
        <div class="text-3xl font-bold text-purple-400 mt-1">{len(albums)}</div>
      </div>
    </div>

    <div class="bg-zinc-900 border border-zinc-800 rounded-xl p-5 space-y-3">
      <h2 class="text-sm font-bold uppercase tracking-wider text-zinc-300">Local Network Access URLs (All Interfaces: {HOST}:{PORT})</h2>
      <div class="flex flex-wrap gap-2">
        {net_badges}
      </div>
    </div>
  </div>
</body>
</html>"""
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html.encode("utf-8"))))
            self.end_headers()
            self.wfile.write(html.encode("utf-8"))
            return

        return super().do_GET()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8") if length > 0 else "{}"
        try:
            payload = json.loads(body)
        except Exception:
            payload = {}

        if path == "/api/auth/login":
            u = payload.get("username", "").strip()
            p = payload.get("password", "")
            conn = get_db()
            row = conn.execute("SELECT username, password_hash FROM users WHERE username = ? AND password_hash = ?", (u, p)).fetchone()
            conn.close()
            if row:
                self.send_json({"token": "demo-session-token", "username": u})
            else:
                self.send_json({"error": "Invalid username or password"}, status=401)
            return

        elif path == "/api/auth/change-credentials":
            curr_user = payload.get("current_username", "").strip()
            curr_pass = payload.get("current_password", "")
            new_user = payload.get("new_username", "").strip()
            new_pass = payload.get("new_password", "")

            if not new_user or not new_pass or len(new_pass) < 4:
                self.send_json({"error": "New username and password (min 4 characters) are required."}, status=400)
                return

            conn = get_db()
            user_row = conn.execute("SELECT id FROM users WHERE username = ? AND password_hash = ?", (curr_user, curr_pass)).fetchone()
            if not user_row:
                conn.close()
                self.send_json({"error": "Current password is incorrect."}, status=401)
                return

            existing = conn.execute("SELECT id FROM users WHERE username = ? AND id != ?", (new_user, user_row["id"])).fetchone()
            if existing:
                conn.close()
                self.send_json({"error": f"Username {new_user} is already in use."}, status=400)
                return

            conn.execute("UPDATE users SET username = ?, password_hash = ? WHERE id = ?", (new_user, new_pass, user_row["id"]))
            conn.commit()
            conn.close()
            self.send_json({"status": "ok", "username": new_user, "message": "Credentials updated successfully."})
            return

        elif path == "/api/media/caption":
            media_id = payload.get("id")
            caption = payload.get("caption", "")
            conn = get_db()
            conn.execute("UPDATE media SET caption = ? WHERE id = ?", (caption, media_id))
            conn.commit()
            conn.close()
            self.send_json({"status": "ok", "id": media_id, "caption": caption})
            return

        elif path == "/api/config":
            conn = get_db()
            if isinstance(payload, list):
                existing_rows = {
                    r["id"]: r for r in conn.execute("SELECT id, album_name, path_location FROM sources_config").fetchall()
                }
                kept_ids = set()
                kept_album_names = set()

                for cfg in payload:
                    album_name = (cfg.get("album_name") or "").strip()
                    path_loc = (cfg.get("path_location") or "").strip()
                    if not album_name or not path_loc:
                        continue
                    cfg_id = cfg.get("id")
                    if cfg_id in existing_rows:
                        old_name = existing_rows[cfg_id]["album_name"]
                        conn.execute(
                            "UPDATE sources_config SET album_name = ?, path_location = ? WHERE id = ?",
                            (album_name, path_loc, cfg_id)
                        )
                        if old_name != album_name:
                            conn.execute(
                                "UPDATE media SET album_name = ? WHERE source_id = ? OR album_name = ?",
                                (album_name, cfg_id, old_name)
                            )
                        kept_ids.add(cfg_id)
                        kept_album_names.add(album_name)
                    else:
                        cur = conn.execute(
                            "INSERT INTO sources_config (album_name, path_location, last_synced) VALUES (?, ?, datetime('now'))",
                            (album_name, path_loc)
                        )
                        kept_ids.add(cur.lastrowid)
                        kept_album_names.add(album_name)

                # Delete any removed sources and their source-owned media
                for old_id, old_row in existing_rows.items():
                    if old_id not in kept_ids:
                        conn.execute("DELETE FROM media WHERE source_id = ?", (old_id,))
                        if old_row["album_name"] not in kept_album_names:
                            conn.execute("DELETE FROM media WHERE album_name = ? AND source_id IS NULL", (old_row["album_name"],))
                        conn.execute("DELETE FROM sources_config WHERE id = ?", (old_id,))

                conn.commit()
                sync_all_sources(conn)
                albums = get_all_albums_summary(conn)
            else:
                albums = get_all_albums_summary(conn)
            conn.close()
            self.send_json({"status": "saved", "albums": albums})
            return

        elif path == "/api/config/delete":
            source_id = payload.get("id")
            album_name = (payload.get("album_name") or "").strip()
            conn = get_db()
            if source_id:
                row = conn.execute("SELECT album_name FROM sources_config WHERE id = ?", (source_id,)).fetchone()
                conn.execute("DELETE FROM media WHERE source_id = ?", (source_id,))
                conn.execute("DELETE FROM sources_config WHERE id = ?", (source_id,))
                if row:
                    remaining = conn.execute("SELECT COUNT(*) FROM sources_config WHERE album_name = ?", (row["album_name"],)).fetchone()[0]
                    if remaining == 0:
                        conn.execute("DELETE FROM media WHERE album_name = ?", (row["album_name"],))
            elif album_name:
                conn.execute("DELETE FROM media WHERE album_name = ?", (album_name,))
                conn.execute("DELETE FROM sources_config WHERE album_name = ?", (album_name,))
            conn.commit()
            albums = get_all_albums_summary(conn)
            conn.close()
            self.send_json({"status": "deleted", "albums": albums})
            return

        elif path == "/api/sync":
            conn = get_db()
            # If the client also sent current sourceConfigurations in the sync request, save them first
            if isinstance(payload, dict) and isinstance(payload.get("sources"), list):
                existing_rows = {
                    r["id"]: r for r in conn.execute("SELECT id, album_name, path_location FROM sources_config").fetchall()
                }
                kept_ids = set()
                for cfg in payload["sources"]:
                    album_name = (cfg.get("album_name") or "").strip()
                    path_loc = (cfg.get("path_location") or "").strip()
                    if not album_name or not path_loc:
                        continue
                    cfg_id = cfg.get("id")
                    if cfg_id in existing_rows:
                        old_name = existing_rows[cfg_id]["album_name"]
                        conn.execute(
                            "UPDATE sources_config SET album_name = ?, path_location = ? WHERE id = ?",
                            (album_name, path_loc, cfg_id)
                        )
                        if old_name != album_name:
                            conn.execute(
                                "UPDATE media SET album_name = ? WHERE source_id = ? OR album_name = ?",
                                (album_name, cfg_id, old_name)
                            )
                        kept_ids.add(cfg_id)
                    else:
                        cur = conn.execute(
                            "INSERT INTO sources_config (album_name, path_location, last_synced) VALUES (?, ?, datetime('now'))",
                            (album_name, path_loc)
                        )
                        kept_ids.add(cur.lastrowid)
                for old_id, old_row in existing_rows.items():
                    if old_id not in kept_ids:
                        conn.execute("DELETE FROM media WHERE source_id = ?", (old_id,))
                        conn.execute("DELETE FROM sources_config WHERE id = ?", (old_id,))
                conn.commit()

            added = sync_all_sources(conn)
            albums = get_all_albums_summary(conn)
            conn.close()
            self.send_json({"status": "synced", "added": added, "albums": albums})
            return

        elif path == "/api/albums/virtual":
            album_name = (payload.get("album_name") or "").strip()
            media_ids = payload.get("media_ids") or []
            if not album_name:
                self.send_json({"error": "Album name is required."}, status=400)
                return

            conn = get_db()
            conn.execute("INSERT OR IGNORE INTO virtual_albums (album_name) VALUES (?)", (album_name,))
            added_count = 0
            if isinstance(media_ids, list) and len(media_ids) > 0:
                placeholders = ",".join(["?"] * len(media_ids))
                valid_rows = conn.execute(f"SELECT id FROM media WHERE id IN ({placeholders})", media_ids).fetchall()
                for vr in valid_rows:
                    cur = conn.execute(
                        "INSERT OR IGNORE INTO virtual_album_items (album_name, media_id) VALUES (?, ?)",
                        (album_name, vr["id"])
                    )
                    if cur.rowcount > 0:
                        added_count += 1
            conn.commit()
            albums = get_all_albums_summary(conn)
            conn.close()
            self.send_json({
                "status": "ok",
                "album_name": album_name,
                "added_count": added_count,
                "albums": albums
            })
            return

        elif path == "/api/albums/virtual/delete":
            album_name = (payload.get("album_name") or "").strip()
            conn = get_db()
            conn.execute("DELETE FROM virtual_album_items WHERE album_name = ?", (album_name,))
            conn.execute("DELETE FROM virtual_albums WHERE album_name = ?", (album_name,))
            conn.execute("DELETE FROM sharing_albums WHERE album_name = ?", (album_name,))
            conn.commit()
            albums = get_all_albums_summary(conn)
            conn.close()
            self.send_json({"status": "deleted", "albums": albums})
            return

        elif path == "/api/share":
            album_name = (payload.get("album_name") or "").strip()
            req_media_ids = payload.get("media_ids") or []
            if not album_name:
                album_name = f"Shared Album {datetime.now().strftime('%Y-%m-%d %H:%M')}"

            conn = get_db()
            valid_ids = []
            if isinstance(req_media_ids, list) and len(req_media_ids) > 0:
                placeholders = ",".join(["?"] * len(req_media_ids))
                rows = conn.execute(f"SELECT id FROM media WHERE id IN ({placeholders})", req_media_ids).fetchall()
                valid_ids = [r["id"] for r in rows]
            else:
                # Look up existing database media linked to this virtual or source album
                rows = conn.execute("""
                    SELECT DISTINCT id FROM media
                    WHERE album_name = ? OR id IN (SELECT media_id FROM virtual_album_items WHERE album_name = ?)
                """, (album_name, album_name)).fetchall()
                valid_ids = [r["id"] for r in rows]

            if not valid_ids:
                conn.close()
                self.send_json({
                    "error": "Cannot share an empty album. Please select or link existing photos from the database first."
                }, status=400)
                return

            # Ensure virtual album & links exist for these valid database media IDs
            conn.execute("INSERT OR IGNORE INTO virtual_albums (album_name) VALUES (?)", (album_name,))
            for mid in valid_ids:
                conn.execute(
                    "INSERT OR IGNORE INTO virtual_album_items (album_name, media_id) VALUES (?, ?)",
                    (album_name, mid)
                )

            share_token = "va_" + secrets.token_urlsafe(9).replace("-", "").replace("_", "")[:12]
            passcode = f"{secrets.randbelow(10000):04d}"

            conn.execute("""
                INSERT INTO sharing_albums (share_token, passcode, album_name, media_ids)
                VALUES (?, ?, ?, ?)
            """, (share_token, passcode, album_name, json.dumps(valid_ids)))
            conn.commit()
            albums = get_all_albums_summary(conn)
            conn.close()

            self.send_json({
                "status": "ok",
                "share_token": share_token,
                "passcode": passcode,
                "album_name": album_name,
                "media_count": len(valid_ids),
                "share_url": f"/?share={share_token}",
                "albums": albums
            })
            return

        elif path == "/api/share/verify":
            token = (payload.get("share_token") or "").strip()
            passcode = (payload.get("passcode") or "").strip()
            conn = get_db()
            row = conn.execute(
                "SELECT share_token, passcode, album_name, media_ids, created_at FROM sharing_albums WHERE share_token = ?",
                (token,)
            ).fetchone()
            if not row:
                conn.close()
                self.send_json({"error": "Shared virtual album not found."}, status=404)
                return
            if row["passcode"] != passcode:
                conn.close()
                self.send_json({"error": "Invalid 4-digit passcode. Access denied."}, status=401)
                return

            try:
                mids = json.loads(row["media_ids"] or "[]")
            except Exception:
                mids = []

            items = []
            if mids:
                placeholders = ",".join(["?"] * len(mids))
                media_rows = conn.execute(
                    f"SELECT id, album_name, file_type, date_taken, latitude, longitude, caption, thumb_hash FROM media WHERE id IN ({placeholders}) ORDER BY date_taken DESC, id DESC",
                    mids
                ).fetchall()
                for r in media_rows:
                    items.append({
                        "id": r["id"],
                        "album_name": row["album_name"],
                        "origin_album": r["album_name"],
                        "file_type": r["file_type"],
                        "date_taken": r["date_taken"],
                        "latitude": r["latitude"],
                        "longitude": r["longitude"],
                        "caption": r["caption"],
                        "thumb_hash": r["thumb_hash"]
                    })
            conn.close()
            self.send_json({
                "status": "ok",
                "share_token": row["share_token"],
                "album_name": row["album_name"],
                "created_at": row["created_at"],
                "total": len(items),
                "items": items
            })
            return

        elif path == "/api/share/delete":
            share_token = (payload.get("share_token") or "").strip()
            conn = get_db()
            conn.execute("DELETE FROM sharing_albums WHERE share_token = ?", (share_token,))
            conn.commit()
            conn.close()
            self.send_json({"status": "deleted", "share_token": share_token})
            return

        self.send_error(404, "Endpoint not found")


class ReusableTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    init_db()
    server = ReusableTCPServer((HOST, PORT), MediaVaultHandler)
    print(f"Memoria server listening on all interfaces ({HOST}:{PORT}):")
    for url in get_local_network_urls():
        print(f"  -> {url}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
