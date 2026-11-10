# System Overview & Architecture — Memoria v2

**Memoria v2** is a self-hosted, privacy-first local photo and video web vault engineered to index, stream, and visualize media libraries across local networks (LAN). It pairs a zero-external-dependency Single-Page Application (SPA) frontend—featuring virtualized responsive grids, multi-theme styling, PhotoSwipe 5 lightboxes with live SQLite caption persistence, and an offline/online hybrid MapLibre GL 3D Globe—with a multi-threaded Python or Rust (Axum + Tokio) backend backed by SQLite in `Write-Ahead Logging` (WAL) mode.

---

## 1. High-Level System Architecture

```mermaid
flowchart TD
    subgraph LAN["Local Area Network (0.0.0.0:8080)"]
        ClientGrid["Browser Client: Responsive Grid & Filters"]
        ClientGlobe["Browser Client: 3D Globe (MapLibre GL v6)"]
        ClientLightbox["Browser Client: PhotoSwipe 5 Lightbox"]
        ClientAdmin["Admin & Diagnostics Dashboard (/admin)"]
    end

    subgraph Container["Docker Container: memoria-local"]
        subgraph Backend["Backend Service (Python ThreadingHTTPServer / Rust Axum)"]
            AuthAPI["Auth & Security API\n(/api/auth/login, /api/auth/change-credentials)"]
            MediaAPI["Media Query & Caption API\n(/api/media, /api/media/albums, /api/media/caption)"]
            StreamAPI["Byte-Stream Engine\n(/api/stream/file/:id)"]
            SyncEngine["Background Directory Scanner\n(/api/sync, /api/config)"]
            NetAPI["LAN Discovery Engine\n(/api/network, /admin)"]
        end

        subgraph Assets["Bundled Static & Map Assets (/app/dist)"]
            VendorJS["Bundled Vendor Modules\n(Tailwind, PhotoSwipe 5, MapLibre GL v6)"]
            GeoJSON["Offline World Map\n(/vendor/world-countries.geojson)"]
        end
    end

    subgraph Storage["Host Storage & Bind Mounts"]
        SQLiteDB[("SQLite3 Database (WAL Mode)\n/data/memoria.db")]
        LocalMedia[("Local Media Shares (Read-Only)\n/media_sources, /mnt, /media")]
    end

    ClientGrid <-->|"REST JSON"| MediaAPI
    ClientGrid <-->|"Lazy Image Stream"| StreamAPI
    ClientGlobe <-->|"Offline Land Vectors"| GeoJSON
    ClientGlobe <-->|"GPS Coordinate Pins"| MediaAPI
    ClientLightbox <-->|"Live Caption Save"| MediaAPI
    ClientAdmin <-->|"Health & LAN URLs"| NetAPI
    ClientGrid <-->|"Session Auth"| AuthAPI

    AuthAPI <--> SQLiteDB
    MediaAPI <--> SQLiteDB
    SyncEngine <--> SQLiteDB
    SyncEngine <-- "Walk Directories (RO)" --> LocalMedia
    StreamAPI <-- "Direct Byte Read (RO)" --> LocalMedia
```

---

## 2. Core Functional Workflows

### 2.1 Authentication & Credential Hardening Workflow

Memoria v2 ships with sandboxed demo credentials (`demo` / `demo`) for immediate evaluation and detects default credentials in the Settings UI, guiding administrators through live credential rotation without restarting the container.

```mermaid
sequenceDiagram
    autonumber
    actor User as Local Network User
    participant SPA as Frontend SPA (index.html)
    participant API as Auth API (/api/auth/*)
    participant DB as SQLite DB (users table)

    User->>SPA: Open http://<LAN-IP>:8080
    SPA->>User: Display Login Modal (Default Demo: demo / demo)
    User->>SPA: Submit username & password
    SPA->>API: POST /api/auth/login { username, password }
    API->>DB: SELECT username FROM users WHERE username=? AND password_hash=?
    alt Valid Credentials
        DB-->>API: Row matched
        API-->>SPA: 200 OK { token: "demo-session-token", username }
        SPA->>SPA: Store session & load albums/media
    else Invalid Credentials
        DB-->>API: None
        API-->>SPA: 401 Unauthorized { error }
        SPA->>User: Show error banner
    end

    opt Rotate Demo Credentials in Settings
        User->>SPA: Open Settings -> Account Security
        SPA->>User: Show "Default demo credentials detected (demo / demo)" banner
        User->>SPA: Submit current password + new username & password
        SPA->>API: POST /api/auth/change-credentials
        API->>DB: Verify current user & UPDATE users SET username=?, password_hash=?
        DB-->>API: Committed (WAL)
        API-->>SPA: 200 OK { status: "ok", username }
        SPA->>User: Update badge to "Secured"
    end
```

### 2.2 Media Indexing, Filtering & Lightbox Inspection Workflow

```mermaid
flowchart LR
    A["Configure Source Paths\n(/api/config)"] --> B["Trigger Sync\n(POST /api/sync)"]
    B --> C["Walk Mounted Folders\n(/media_sources, /mnt, /media)"]
    C --> D["Index Metadata & GPS\ninto SQLite media table"]
    D --> E["Query Paginated Media\n(GET /api/media)"]
    E --> F{"Select View Mode"}
    F -->|"Grid View"| G["Render Responsive Grid\n(3-10 Columns, Lazy Load)"]
    F -->|"3D Globe View"| H["Render MapLibre 3D Globe\nwith GPS Thumbnail Pins"]
    G --> I["Click Photo -> Open PhotoSwipe 5"]
    H --> I
    I --> J["Inspect GPS Badge & Edit Caption\n(POST /api/media/caption)"]
```

### 2.3 3D Globe Rendering Pipeline

To ensure the 3D Globe functions reliably across both offline local networks and internet-connected environments, Memoria v2 uses a multi-layered rendering pipeline:

1. **WebWorker Pre-Configuration:** Configures `maplibregl.setWorkerUrl('/vendor/maplibre-gl-worker.mjs')` so ES module workers initialize cleanly from local static storage.
2. **Offline Base Vector Layer:** Loads bundled Natural Earth country polygons (`/vendor/world-countries.geojson`) for immediate continent fills (`#1e3e62`) and country borders (`#3b82f6`) over a deep-ocean sphere (`#0b192c`).
3. **Hybrid Raster Detail Layer:** Overlays OpenStreetMap raster tiles (`https://tile.openstreetmap.org/{z}/{x}/{y}.png`) when internet connectivity is available for street-level zoom inspection.
4. **Interactive Photo Pin Anchors:** Projects every media item with valid `latitude` and `longitude` onto the 3D sphere as a circular thumbnail pin that opens the exact image inside the PhotoSwipe lightbox when clicked.

---

## 3. Database Schema (SQLite WAL)

```mermaid
erDiagram
    users {
        INTEGER id PK
        TEXT username UK "Default: demo"
        TEXT password_hash "Default: demo"
        DATETIME created_at
    }
    sources_config {
        INTEGER id PK
        TEXT album_name
        TEXT path_location UK
        TEXT tags
        DATETIME last_synced
    }
    media {
        INTEGER id PK
        INTEGER source_id FK
        TEXT album_name
        TEXT file_path UK
        TEXT file_type "image | video"
        TEXT date_taken "ISO-8601"
        REAL latitude "Nullable GPS Lat"
        REAL longitude "Nullable GPS Lon"
        TEXT caption "Editable note"
        TEXT thumb_hash
        TEXT tags
    }
    sources_config ||--o{ media : "indexes"
```

---

## 4. Security & Demo Configuration Model

| Layer | Configuration | Default / Demo Value | Production Hardening |
| :--- | :--- | :--- | :--- |
| **Authentication** | Initial Seed Account | `demo` / `demo` | Rotate immediately via **⚙️ Settings $\rightarrow$ Account Security** (`POST /api/auth/change-credentials`). |
| **Network Binding** | Container & Host Port | `0.0.0.0:8080->8080/tcp` | Restrict to localhost (`127.0.0.1:8080:8080`) if placing behind an HTTPS reverse proxy (Nginx / Caddy / Traefik). |
| **LAN Discovery** | `HOST_NETWORK_URLS` | `http://memoria-demo.local:8080`, `http://192.168.1.100:8080` | Override via `HOST_NETWORK_URLS` or set `AUTO_DETECT_LAN=1` in `docker-compose.yml`. |
| **Storage Mounts** | Media Volume Permissions | `:ro` (Read-Only) | Media shares (`/media_sources`, `/mnt`, `/media`) are mounted read-only so the container can never modify or delete original files. |
| **Database Isolation** | SQLite WAL Volume | `./data:/data` (`rw`) | Excluded from Git via `.gitignore` (`data/*.db*`) so user credentials and private metadata are never committed. |
