# Memoria v2: Self-Hosted Local Photo & Video Web Vault

**Memoria v2** is a self-hosted, browser-based photo and video vault engineered to index, stream, and visualize local media folders and network shares across your Local Area Network (LAN). It features a responsive multi-theme grid, dynamic PhotoSwipe 5 lightboxes with live SQLite caption editing, an offline/online hybrid MapLibre GL v6 3D Globe viewer with EXIF GPS thumbnail pins, and full LAN discovery.

> [!TIP]
> For deep-dive sequence diagrams, ER diagrams, and security model details, see [ARCHITECTURE.md](ARCHITECTURE.md).

---

## 1. System Overview & Architecture

```mermaid
flowchart TD
    subgraph LAN["Local Area Network Clients (0.0.0.0:8080)"]
        UI_Grid["Responsive Gallery Grid\n(3-10 Cols, Search, Date & Album Filters)"]
        UI_Globe["Interactive 3D Globe\n(MapLibre GL v6 + Offline GeoJSON + OSM)"]
        UI_PSWP["PhotoSwipe 5 Lightbox\n(GPS Coordinates Badge + Live Caption Editor)"]
        UI_Admin["Backend Diagnostics Dashboard\n(GET /admin)"]
    end

    subgraph Docker["Docker Container: memoria-local"]
        Server["Multi-Threaded HTTP & API Server\n(server.py / Rust Axum)"]
        Static["Bundled Local Vendor Assets\n(dist/vendor/* + world-countries.geojson)"]
    end

    subgraph Storage["Host Storage & Read-Only Media Shares"]
        DB[("SQLite3 WAL Database\n./data/memoria.db")]
        Media[("Photo & Video Directories\n./media_sources, /mnt, /media (:ro)")]
    end

    UI_Grid <-->|"JSON & Image Streams"| Server
    UI_Globe <-->|"GeoJSON + GPS Pins"| Server
    UI_PSWP <-->|"POST /api/media/caption"| Server
    UI_Admin <-->|"GET /api/network & Status"| Server
    Server <-->|"Serving Static SPA"| Static
    Server <-->|"Read/Write Metadata & Auth"| DB
    Server <-- "Read-Only File Walk & Stream" --> Media
```

### Core Capabilities & v2 Enhancements
* **Full Local Network (LAN) Access:** Binds to `0.0.0.0:8080` with multi-threaded request handling (`ThreadingMixIn`) so multiple devices on your Wi-Fi/LAN can browse and stream media concurrently.
* **Hybrid Offline/Online 3D Globe (`MapLibre GL v6`):** Renders a true 3D Earth sphere (`projection: { type: 'globe' }`) using bundled offline country boundary vectors (`/vendor/world-countries.geojson`) layered with OpenStreetMap raster tiles and interactive photo pins for every geotagged image.
* **Demo-Safe Security & Live Credential Rotation:** Ships with default demo credentials (`demo` / `demo`) and an automatic security banner in **⚙️ Settings** allowing instant username/password updates directly to SQLite without container restarts.
* **Zero External JS/CSS Dependencies:** Tailwind CSS, PhotoSwipe 5, MapLibre GL JS v6, WebWorkers, and world vector maps are bundled locally in `dist/vendor/`.

---

## 2. Application Workflow

```mermaid
sequenceDiagram
    autonumber
    actor User as LAN User
    participant Browser as Memoria SPA
    participant Backend as memoria-local (:8080)
    participant SQLite as SQLite (WAL)

    User->>Browser: Navigate to http://<HOST-IP>:8080
    Browser->>User: Prompt Login (Default Demo: demo / demo)
    User->>Browser: Sign In (demo / demo)
    Browser->>Backend: POST /api/auth/login
    Backend->>SQLite: Verify credentials in users table
    SQLite-->>Backend: Validated
    Backend-->>Browser: 200 OK { token, username }

    Browser->>Backend: GET /api/media/albums & GET /api/media?limit=40&offset=0
    Backend->>SQLite: Query indexed albums & media rows
    SQLite-->>Backend: Return metadata + GPS coordinates
    Backend-->>Browser: Render Gallery Grid

    alt Switch to 3D Globe View
        User->>Browser: Click "Globe" button
        Browser->>Backend: Load /vendor/world-countries.geojson
        Browser->>Browser: Initialize 3D Globe & plot GPS photo pins
        User->>Browser: Click photo pin on 3D Globe
        Browser->>Browser: Open PhotoSwipe 5 Lightbox with GPS badge
    else Edit Photo Caption
        User->>Browser: Click photo -> Click 💬 -> Edit Caption -> Save
        Browser->>Backend: POST /api/media/caption { id, caption }
        Backend->>SQLite: UPDATE media SET caption = ? WHERE id = ?
        SQLite-->>Backend: Saved
        Backend-->>Browser: 200 OK
    end
```

---

## 3. Visual Previews & Screenshots

| 1. Demo Authentication Gate (`demo / demo`) | 2. Virtualized Gallery Grid & Album Catalog |
| :---: | :---: |
| ![Login Gate](screenshots/00_login_gate.png) | ![Frontend Grid](screenshots/01_frontend_grid_view.png) |

| 3. Collapsible Date Range Filter | 4. Settings, Security & LAN Access Modal |
| :---: | :---: |
| ![Date Filter](screenshots/02_frontend_date_filter_popover.png) | ![Settings Modal](screenshots/03_frontend_settings_modal.png) |

| 5. Interactive 3D Globe Viewer | 6. PhotoSwipe Lightbox & Caption Editor |
| :---: | :---: |
| ![3D Globe](screenshots/04_frontend_globe_3d.png) | ![PhotoSwipe Lightbox](screenshots/06_frontend_photoswipe_lightbox.png) |

| 7. Backend Diagnostics & LAN Discovery Dashboard (`/admin`) |
| :---: |
| ![Backend Diagnostics](screenshots/05_backend_diagnostics_page.png) |

---

## 4. Repository File Layout

```text
Memoria-v2/
├── ARCHITECTURE.md                   # Detailed architecture, sequence & ER diagrams
├── README.md                         # Deployment guide & documentation
├── Dockerfile                        # Container build with Python 3.12, FFmpeg & SQLite3
├── docker-compose.yml                # "memoria-local" service definition & LAN port bindings
├── Cargo.toml                        # Optional Rust (Axum + Tokio + SQLx) build manifest
├── server.py                         # Multi-threaded Python backend & diagnostics server
├── src/
│   └── main.rs                       # Rust Axum backend server implementation
├── dist/
│   ├── index.html                    # Single-Page Application (Grid, 3D Globe, Lightbox, Settings)
│   └── vendor/                       # Bundled offline assets (MapLibre, PhotoSwipe, Tailwind, GeoJSON)
├── media_sources/                    # Sample photography albums (Nature, Cities, California, Japan)
└── screenshots/                      # Full UI screenshots across all views
```

---

## 5. Deployment Instructions

### Prerequisites
* **Docker** (v20.10+) and **Docker Compose** (or `docker run`) installed.
* Or **Python 3.10+** for standalone host execution.

---

### Option A: Deploy with Docker (`memoria-local` on Port 8080)

#### 1. Clone the Repository
```bash
git clone https://github.com/chiuhung0508/Memoria-v2.git
cd Memoria-v2
mkdir -p data
```

#### 2. Build & Launch the `memoria-local` Container
Using `docker build` and `docker run` (works on all Docker installations with or without the Compose plugin):

```bash
docker build -t memoria-local:latest .

docker run -d \
  --name memoria-local \
  --restart unless-stopped \
  -p 0.0.0.0:8080:8080 \
  -v "$(pwd)/data:/data" \
  -v "$(pwd)/media_sources:/app/media_sources:ro" \
  -v "$(pwd)/media_sources:/media_sources:ro" \
  -v /mnt:/mnt:ro \
  -v /media:/media:ro \
  -e HOST=0.0.0.0 \
  -e PORT=8080 \
  -e DB_PATH=/data/memoria.db \
  -e "HOST_NETWORK_URLS=http://memoria-demo.local:8080,http://192.168.1.100:8080" \
  memoria-local:latest
```

*(Alternatively, if `docker compose` is installed, run `docker compose up --build -d`.)*

#### 3. Verify Container & Logs
```bash
docker ps --filter name=memoria-local
docker logs memoria-local
```

---

### Option B: Standalone Local Deployment (Python)

Run the multi-threaded Python server directly on your host:

```bash
python3 server.py
```

---

## 6. Accessing & Configuring Memoria on Your Local Network

1. **Open the Web Vault:**
   * **On the host machine:** `http://localhost:8080`
   * **From any device on your local network:** `http://<YOUR-LAN-IP>:8080`
   * **Backend Diagnostics Dashboard:** `http://<YOUR-LAN-IP>:8080/admin`
2. **Sign In with Demo Credentials:**
   * **Username:** `demo`
   * **Password:** `demo`
3. **Harden Account Credentials:**
   * Click **⚙️ Settings** in the top navigation bar.
   * Under **🔐 Account Security & Credentials**, enter the current demo password (`demo`), specify your new custom username and strong password (minimum 4 characters), and click **Update Credentials**.
4. **Add & Sync Custom Photo/Video Folders:**
   * In **⚙️ Settings $\rightarrow$ Source Directories & SMB Shares**, click **+ Add Path**.
   * Enter an Album Name and container-mounted path (e.g., `/mnt/nas_photos` or `/media/usb_drive`).
   * Click **Save Sources**, then click **🔄 Reload Index & Sync Database**.
