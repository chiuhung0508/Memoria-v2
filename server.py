#!/usr/bin/env python3
import http.server
import socketserver
import socket
import subprocess
import json
import sqlite3
import os
import io
import hashlib
import secrets
import urllib.parse
from datetime import datetime

try:
    import smbclient
    from smbprotocol.exceptions import SMBException, SMBAuthenticationError, SMBResponseException
    HAS_SMB = True
except Exception:
    HAS_SMB = False

try:
    from PIL import Image, ExifTags, ImageOps
    HAS_PIL = True
except Exception:
    HAS_PIL = False

HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", 8080))
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DB_PATH", os.path.join(BASE_DIR, "data", "memoria.db"))
SMB_CACHE_DIR = os.path.join(os.path.dirname(DB_PATH), "smb_cache")
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


def is_smb_path(raw_path):
    if not raw_path:
        return False
    p = raw_path.strip()
    return p.startswith("//") or p.startswith("\\\\") or p.lower().startswith("smb://")


def parse_smb_path(raw_path):
    if not raw_path:
        return None
    p = raw_path.strip()
    if p.lower().startswith("smb://"):
        p = p[6:]
    elif p.startswith("//"):
        p = p[2:]
    elif p.startswith("\\\\"):
        p = p[2:]
    else:
        return None

    p = p.replace("\\", "/").strip("/")
    parts = [seg for seg in p.split("/") if seg]
    if len(parts) < 2:
        return None
    server = parts[0]
    share = parts[1]
    subpath = "/".join(parts[2:])
    normalized = f"//{server}/{share}" + (f"/{subpath}" if subpath else "")
    return server, share, subpath, normalized


def resolve_smb_host(server):
    for candidate in (server, f"{server}.home", f"{server}.local"):
        try:
            info = socket.getaddrinfo(candidate, 445, socket.AF_INET, socket.SOCK_STREAM)
            if info:
                return info[0][4][0]
        except Exception:
            pass
    return server


def resolve_source_path(raw_path):
    if not raw_path:
        return ""
    p = raw_path.strip()
    if is_smb_path(p):
        return p
    if os.path.exists(p):
        return p
    for prefix in ("/app/media_sources", "/media_sources", "media_sources"):
        if p == prefix or p.startswith(prefix + "/"):
            sub = p[len(prefix):].lstrip("/")
            candidate = os.path.join(SOURCES_DIR, sub) if sub else SOURCES_DIR
            if os.path.exists(candidate):
                return candidate
    return p


def format_file_size(num_bytes):
    if not num_bytes or num_bytes <= 0:
        return "—"
    if num_bytes < 1024:
        return f"{num_bytes} B"
    elif num_bytes < 1024 * 1024:
        return f"{num_bytes / 1024:.1f} KB ({num_bytes:,} bytes)"
    else:
        return f"{num_bytes / (1024 * 1024):.2f} MB ({num_bytes:,} bytes)"


def _to_float(val):
    try:
        if hasattr(val, "numerator") and hasattr(val, "denominator"):
            return float(val.numerator) / float(val.denominator) if val.denominator else 0.0
        if isinstance(val, tuple) and len(val) == 2:
            return float(val[0]) / float(val[1]) if val[1] else 0.0
        return float(val)
    except Exception:
        return None


def _clean_str(val):
    if val is None:
        return ""
    if isinstance(val, bytes):
        if val.startswith(b"ASCII\x00\x00\x00"):
            val = val[8:]
        try:
            s = val.decode("utf-8", errors="ignore")
        except Exception:
            s = ""
    else:
        s = str(val)
    if s.startswith("ASCII"):
        s = s[5:]
    return s.replace("\x00", "").strip()


FLASH_MAP = {
    0x00: "No Flash",
    0x01: "Fired",
    0x05: "Fired, Return not detected",
    0x07: "Fired, Return detected",
    0x08: "On, Did not fire",
    0x09: "On, Fired",
    0x0D: "On, Return not detected",
    0x0F: "On, Return detected",
    0x10: "Off, Did not fire",
    0x18: "Auto, Did not fire",
    0x19: "Auto, Fired",
    0x1D: "Auto, Fired, Return not detected",
    0x1F: "Auto, Fired, Return detected",
    0x20: "No flash function",
    0x41: "Fired, Red-eye reduction",
    0x45: "Fired, Red-eye reduction, Return not detected",
    0x47: "Fired, Red-eye reduction, Return detected",
    0x49: "On, Red-eye reduction",
    0x59: "Auto, Fired, Red-eye reduction"
}

METERING_MAP = {
    0: "Unknown", 1: "Average", 2: "Center-weighted average",
    3: "Spot", 4: "Multi-spot", 5: "Multi-segment (Pattern)", 6: "Partial"
}

EXPOSURE_PROG_MAP = {
    0: "Not Defined", 1: "Manual", 2: "Normal Program", 3: "Aperture Priority",
    4: "Shutter Priority", 5: "Creative Program", 6: "Action Program",
    7: "Portrait Mode", 8: "Landscape Mode"
}


def extract_full_metadata(local_file_path, display_filename=None, fallback_dt=None, fallback_lat=None, fallback_lon=None):
    """
    Extracts image dimensions (width, height) and builds the 7-group structured EXIF dictionary
    for persistence in the SQLite media table.
    """
    fname = display_filename or os.path.basename(local_file_path or "")
    ext = os.path.splitext(fname)[1].lower()
    mime_map = {".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png", ".webp": "image/webp"}
    mime_type = mime_map.get(ext, "image/jpeg")

    fsize = 0
    if local_file_path and os.path.exists(local_file_path):
        try:
            fsize = os.path.getsize(local_file_path)
        except Exception:
            fsize = 0

    width, height = 0, 0
    color_space = "sRGB"
    has_thumb = "No embedded thumbnail"
    raw_tags = {}
    gps_tags = {}

    if HAS_PIL and local_file_path and os.path.exists(local_file_path):
        try:
            with Image.open(local_file_path) as img:
                width, height = img.size
                mode = img.mode or "RGB"
                # Collect EXIF tags
                try:
                    exif_obj = img.getexif()
                    if exif_obj:
                        for k, v in exif_obj.items():
                            raw_tags[ExifTags.TAGS.get(k, str(k))] = v
                        if hasattr(ExifTags, "IFD"):
                            for ifd_enum in (ExifTags.IFD.Exif,):
                                try:
                                    sub_ifd = exif_obj.get_ifd(ifd_enum)
                                    for k, v in sub_ifd.items():
                                        raw_tags[ExifTags.TAGS.get(k, str(k))] = v
                                except Exception:
                                    pass
                            try:
                                gps_ifd = exif_obj.get_ifd(ExifTags.IFD.GPSInfo)
                                for k, v in gps_ifd.items():
                                    gps_tags[ExifTags.GPSTAGS.get(k, str(k))] = v
                            except Exception:
                                pass
                except Exception:
                    pass

                # Fallback to _getexif() if needed
                if not raw_tags and hasattr(img, "_getexif"):
                    try:
                        legacy = img._getexif() or {}
                        for k, v in legacy.items():
                            tname = ExifTags.TAGS.get(k, str(k))
                            if tname == "GPSInfo" and isinstance(v, dict):
                                for gk, gv in v.items():
                                    gps_tags[ExifTags.GPSTAGS.get(gk, str(gk))] = gv
                            else:
                                raw_tags[tname] = v
                    except Exception:
                        pass

                # Check Orientation to transpose width/height if rotated 90/270 deg
                orient = raw_tags.get("Orientation")
                if orient in (5, 6, 7, 8):
                    width, height = height, width

                cs_val = raw_tags.get("ColorSpace")
                if cs_val == 1:
                    color_space = f"sRGB ({mode})"
                elif cs_val == 65535:
                    color_space = f"Uncalibrated ({mode})"
                else:
                    color_space = f"{mode} (sRGB)"
        except Exception:
            pass

    # 1. Camera info
    make = _clean_str(raw_tags.get("Make"))
    model = _clean_str(raw_tags.get("Model"))
    if make and model:
        make_model = model if model.lower().startswith(make.lower()) else f"{make} {model}"
    else:
        make_model = make or model or "—"

    lens_make = _clean_str(raw_tags.get("LensMake"))
    lens_model = _clean_str(raw_tags.get("LensModel") or raw_tags.get("LensSpecification"))
    lens_str = f"{lens_make} {lens_model}".strip() if (lens_make or lens_model) else "—"

    fl_val = _to_float(raw_tags.get("FocalLength"))
    fl_35 = raw_tags.get("FocalLengthIn35mmFilm")
    if fl_val:
        focal_length = f"{fl_val:.1f} mm" + (f" ({fl_35} mm eq.)" if fl_35 else "")
    else:
        focal_length = "—"

    fnum = _to_float(raw_tags.get("FNumber") or raw_tags.get("ApertureValue"))
    aperture = f"f/{fnum:.1f}" if fnum else "—"

    exp_val = raw_tags.get("ExposureTime")
    exp_float = _to_float(exp_val)
    if exp_float:
        if exp_float < 1.0 and exp_float > 0:
            denom = int(round(1.0 / exp_float))
            exposure = f"1/{denom} sec"
        else:
            exposure = f"{exp_float:.2f} sec"
    else:
        exposure = "—"

    iso_val = raw_tags.get("ISOSpeedRatings") or raw_tags.get("PhotographicSensitivity")
    if isinstance(iso_val, (list, tuple)):
        iso_val = iso_val[0] if iso_val else None
    iso_str = f"ISO {iso_val}" if iso_val else "—"

    flash_val = raw_tags.get("Flash")
    flash_str = FLASH_MAP.get(int(flash_val), f"Mode {flash_val}") if isinstance(flash_val, int) else "—"

    # 3. GPS data
    lat = fallback_lat
    lon = fallback_lon
    if "GPSLatitude" in gps_tags and "GPSLatitudeRef" in gps_tags and "GPSLongitude" in gps_tags and "GPSLongitudeRef" in gps_tags:
        try:
            def dms_to_deg(dms):
                return (_to_float(dms[0]) or 0.0) + ((_to_float(dms[1]) or 0.0) / 60.0) + ((_to_float(dms[2]) or 0.0) / 3600.0)
            lat = round(dms_to_deg(gps_tags["GPSLatitude"]), 6)
            if _clean_str(gps_tags["GPSLatitudeRef"]).upper() == "S":
                lat = -lat
            lon = round(dms_to_deg(gps_tags["GPSLongitude"]), 6)
            if _clean_str(gps_tags["GPSLongitudeRef"]).upper() == "W":
                lon = -lon
        except Exception:
            pass

    alt_val = _to_float(gps_tags.get("GPSAltitude"))
    alt_ref = gps_tags.get("GPSAltitudeRef", 0)
    if alt_val is not None:
        altitude_str = f"{alt_val:.1f} m {'Below' if alt_ref in (1, b'\\x01') else 'Above'} Sea Level"
    else:
        altitude_str = "—"

    dir_val = _to_float(gps_tags.get("GPSImgDirection") or gps_tags.get("GPSTrack"))
    spd_val = _to_float(gps_tags.get("GPSSpeed"))
    spd_ref = _clean_str(gps_tags.get("GPSSpeedRef")) or "km/h"
    dir_parts = []
    if dir_val is not None:
        dir_parts.append(f"{dir_val:.1f}°")
    if spd_val is not None:
        dir_parts.append(f"{spd_val:.1f} {spd_ref}")
    dir_speed_str = " / ".join(dir_parts) if dir_parts else "—"

    lat_str = f"{abs(lat):.5f}° {'N' if lat >= 0 else 'S'} ({lat:.5f})" if lat is not None else "—"
    lon_str = f"{abs(lon):.5f}° {'E' if lon >= 0 else 'W'} ({lon:.5f})" if lon is not None else "—"

    # 4. Copyright info
    creator = _clean_str(raw_tags.get("Artist") or raw_tags.get("XPAuthor") or raw_tags.get("CameraOwnerName")) or "—"
    copyright_txt = _clean_str(raw_tags.get("Copyright")) or "—"
    right_holder = copyright_txt if copyright_txt != "—" else creator
    legal_notice = _clean_str(raw_tags.get("ImageDescription") or raw_tags.get("UserComment")) or "—"

    # 5. Other data
    dt_raw = _clean_str(raw_tags.get("DateTimeOriginal") or raw_tags.get("DateTimeDigitized") or raw_tags.get("DateTime"))
    if dt_raw and len(dt_raw) >= 10 and dt_raw[4] == ":":
        dt_raw = dt_raw.replace(":", "-", 2)
    date_taken = dt_raw or fallback_dt or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    has_thumb = "Embedded EXIF Thumbnail" if ("JPEGInterchangeFormat" in raw_tags or "ThumbnailImage" in raw_tags) else f"Standard Stream ({width}×{height})"

    # 6. Processing software
    software = _clean_str(raw_tags.get("Software") or raw_tags.get("ProcessingSoftware")) or "—"

    # 7. Other (if any)
    other_items = []
    if "WhiteBalance" in raw_tags:
        wb = raw_tags["WhiteBalance"]
        other_items.append({"label": "White Balance", "value": "Manual" if wb == 1 else "Auto"})
    if "MeteringMode" in raw_tags:
        mm = raw_tags["MeteringMode"]
        other_items.append({"label": "Metering Mode", "value": METERING_MAP.get(mm, str(mm))})
    if "ExposureProgram" in raw_tags:
        ep = raw_tags["ExposureProgram"]
        other_items.append({"label": "Exposure Program", "value": EXPOSURE_PROG_MAP.get(ep, str(ep))})
    if "ExposureBiasValue" in raw_tags:
        eb = _to_float(raw_tags["ExposureBiasValue"])
        if eb is not None:
            other_items.append({"label": "Exposure Bias", "value": f"{eb:+.1f} EV"})
    if "Orientation" in raw_tags:
        other_items.append({"label": "Orientation", "value": f"Tag {raw_tags['Orientation']} (Normalized)"})
    if "XResolution" in raw_tags and "YResolution" in raw_tags:
        xr = _to_float(raw_tags["XResolution"])
        yr = _to_float(raw_tags["YResolution"])
        if xr and yr:
            other_items.append({"label": "Resolution", "value": f"{int(xr)} × {int(yr)} DPI"})
    if width and height:
        megapixels = (width * height) / 1_000_000.0
        aspect = round(width / height, 2) if height else 1.0
        other_items.append({"label": "Megapixels & Ratio", "value": f"{megapixels:.2f} MP (Ratio {aspect}:1)"})

    grouped_exif = {
        "camera_info": {
            "make_model": make_model,
            "lens": lens_str,
            "focal_length": focal_length,
            "aperture": aperture,
            "exposure": exposure,
            "iso_speed": iso_str,
            "flash": flash_str
        },
        "image_properties": {
            "file_name": fname,
            "file_size": format_file_size(fsize),
            "mime_type": mime_type,
            "image_size": f"{width} × {height} px" if (width and height) else "—",
            "color_space": color_space
        },
        "gps_data": {
            "latitude": lat_str,
            "longitude": lon_str,
            "raw_lat": lat,
            "raw_lon": lon,
            "altitude": altitude_str,
            "direction_speed": dir_speed_str
        },
        "copyright_info": {
            "creator": creator,
            "copyright": copyright_txt,
            "right_holder": right_holder,
            "legal_notice": legal_notice
        },
        "other_data": {
            "date_time": date_taken,
            "thumbnails": has_thumb
        },
        "processing_software": {
            "software": software
        },
        "other": other_items
    }

    return width, height, fsize, date_taken, lat, lon, grouped_exif


def test_or_sync_smb_share(raw_path, smb_user="", smb_pass="", conn=None, src_id=None, album_name=None):
    if not HAS_SMB:
        return False, "Python smbprotocol module is not installed.", 0

    parsed = parse_smb_path(raw_path)
    if not parsed:
        return False, f"Invalid SMB path format: {raw_path} (Expected //server/share/folder)", 0

    server, share, subpath, normalized = parsed
    target_host = resolve_smb_host(server)
    unc_base = f"\\\\{target_host}\\{share}" + (f"\\{subpath.replace('/', '\\')}" if subpath else "")

    user = (smb_user or "").strip()
    pw = smb_pass or ""

    try:
        smbclient.reset_connection_cache()
        if user:
            smbclient.register_session(target_host, username=user, password=pw, connection_timeout=6)
        else:
            smbclient.register_session(target_host, username="guest", password="", connection_timeout=6)

        list(smbclient.scandir(unc_base))
    except Exception as e:
        err_str = str(e)
        if "0xc0000072" in err_str or "ACCOUNT_DISABLED" in err_str or not user:
            return (
                False,
                f"SMB Auth Required on {server} ({target_host}): Guest access is disabled on this NAS. Enter your NAS SMB Username & Password in Settings.",
                0
            )
        elif "0xc000006d" in err_str or "LOGON_FAILURE" in err_str or "SMBAuthenticationError" in type(e).__name__:
            return (
                False,
                f"SMB Login Failed on {server} ({target_host}) for user '{user}': Invalid username or password.",
                0
            )
        elif "0xc0000034" in err_str or "0xc000003a" in err_str or "OBJECT_NAME_NOT_FOUND" in err_str or "OBJECT_PATH_NOT_FOUND" in err_str:
            return (
                False,
                f"Connected to {server}, but folder '{subpath or share}' was not found on share '{share}'.",
                0
            )
        return False, f"SMB Error ({server}): {err_str[:160]}", 0

    media_files = []
    try:
        for root, _, files in smbclient.walk(unc_base):
            for fname in sorted(files):
                if fname.lower().endswith((".jpg", ".jpeg", ".png", ".webp")):
                    full_unc = root.rstrip("\\") + "\\" + fname
                    rel_from_host = full_unc.lstrip("\\").split("\\", 1)[1].replace("\\", "/")
                    canonical_smb_uri = f"smb://{server}/{rel_from_host}"
                    media_files.append((canonical_smb_uri, full_unc, fname))
    except Exception as e:
        return False, f"Error scanning SMB directory: {str(e)[:140]}", 0

    if conn is not None and src_id is not None and album_name:
        os.makedirs(SMB_CACHE_DIR, exist_ok=True)
        for smb_uri, full_unc, fname in media_files:
            existing = conn.execute(
                "SELECT id, width, height, exif_json FROM media WHERE album_name = ? AND file_path = ? LIMIT 1",
                (album_name, smb_uri)
            ).fetchone()
            if existing and existing["width"] and existing["exif_json"]:
                continue

            dt_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            try:
                st = smbclient.stat(full_unc)
                if st and st.st_mtime:
                    dt_str = datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                pass

            # Cache file locally so we can extract true dimensions & EXIF metadata immediately
            ext = os.path.splitext(fname)[1].lower() or ".jpg"
            url_hash = hashlib.sha1(smb_uri.encode("utf-8")).hexdigest()[:12]
            temp_cache = os.path.join(SMB_CACHE_DIR, f"smb_{url_hash}{ext}")
            if not os.path.exists(temp_cache) or os.path.getsize(temp_cache) == 0:
                try:
                    with smbclient.open_file(full_unc, mode="rb") as rf:
                        data = rf.read()
                    if data:
                        with open(temp_cache, "wb") as wf:
                            wf.write(data)
                except Exception:
                    pass

            w, h, fsize, dt_extracted, lat, lon, exif_dict = extract_full_metadata(
                temp_cache if os.path.exists(temp_cache) else None,
                display_filename=fname,
                fallback_dt=dt_str
            )
            if existing:
                conn.execute("""
                    UPDATE media
                    SET width = ?, height = ?, date_taken = ?, latitude = COALESCE(latitude, ?), longitude = COALESCE(longitude, ?), exif_json = ?
                    WHERE id = ?
                """, (w, h, dt_extracted, lat, lon, json.dumps(exif_dict), existing["id"]))
            else:
                conn.execute("""
                    INSERT OR IGNORE INTO media (source_id, album_name, file_path, file_type, date_taken, latitude, longitude, caption, width, height, exif_json)
                    VALUES (?, ?, ?, 'image', ?, ?, ?, ?, ?, ?, ?)
                """, (src_id, album_name, smb_uri, dt_extracted, lat, lon, "", w, h, json.dumps(exif_dict)))
        conn.commit()

    return True, f"Connected to {normalized} ({len(media_files)} media files indexed)", len(media_files)


def fetch_smb_file_cached(media_id, smb_uri, conn):
    os.makedirs(SMB_CACHE_DIR, exist_ok=True)
    ext = os.path.splitext(smb_uri)[1].lower() or ".jpg"
    url_hash = hashlib.sha1(smb_uri.encode("utf-8")).hexdigest()[:12]
    # Check both media-specific and hash-specific cache paths
    for candidate in (
        os.path.join(SMB_CACHE_DIR, f"media_{media_id}_{url_hash}{ext}"),
        os.path.join(SMB_CACHE_DIR, f"smb_{url_hash}{ext}")
    ):
        if os.path.exists(candidate) and os.path.getsize(candidate) > 0:
            return candidate

    cache_file = os.path.join(SMB_CACHE_DIR, f"media_{media_id}_{url_hash}{ext}")
    parsed = parse_smb_path(smb_uri)
    if not parsed or not HAS_SMB:
        return None
    server, share, subpath, _ = parsed
    target_host = resolve_smb_host(server)
    unc_file = f"\\\\{target_host}\\{share}\\{subpath.replace('/', '\\')}"

    src_row = conn.execute("""
        SELECT s.smb_username, s.smb_password
        FROM media m
        LEFT JOIN sources_config s ON s.id = m.source_id
        WHERE m.id = ?
    """, (media_id,)).fetchone()
    user = ""
    pw = ""
    if src_row and src_row["smb_username"]:
        user = src_row["smb_username"]
        pw = src_row["smb_password"] or ""
    else:
        any_src = conn.execute(
            "SELECT smb_username, smb_password FROM sources_config WHERE path_location LIKE ? AND smb_username != '' LIMIT 1",
            (f"%{server}%",)
        ).fetchone()
        if any_src:
            user = any_src["smb_username"]
            pw = any_src["smb_password"] or ""

    try:
        if user:
            smbclient.register_session(target_host, username=user, password=pw, connection_timeout=6)
        else:
            smbclient.register_session(target_host, username="guest", password="", connection_timeout=6)

        with smbclient.open_file(unc_file, mode="rb") as rf:
            data = rf.read()
        if data:
            with open(cache_file, "wb") as wf:
                wf.write(data)
            return cache_file
    except Exception:
        pass
    return None


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def backfill_media_exif(conn):
    """
    Ensures every row in media has accurate width, height, and pre-computed exif_json in SQLite
    for instantaneous <1ms frontend rendering.
    """
    rows = conn.execute(
        "SELECT id, album_name, file_path, date_taken, latitude, longitude, width, height, exif_json FROM media"
    ).fetchall()

    demo_camera_profiles = {
        "Nature & Wilderness": ("Sony ILCE-7RM5", "FE 24-70mm F2.8 GM II", "24.0 mm", "f/8.0", "1/320 sec", "ISO 100", "Adobe Lightroom Classic 13.2"),
        "European Summer Tour": ("Leica Q3", "Summilux 28mm f/1.7 ASPH.", "28.0 mm", "f/4.0", "1/500 sec", "ISO 125", "Capture One 16.3"),
        "California Road Trip": ("Canon EOS R5", "RF 15-35mm F2.8 L IS USM", "35.0 mm", "f/5.6", "1/640 sec", "ISO 160", "Canon Digital Photo Professional"),
        "Travel to Japan 2025": ("Fujifilm X-T5", "XF 23mm F1.4 R LM WR", "23.0 mm (35 mm eq.)", "f/2.0", "1/160 sec", "ISO 640", "FUJIFILM X RAW STUDIO")
    }

    updated = False
    for r in rows:
        if r["width"] and r["height"] and r["exif_json"]:
            continue
        fpath = r["file_path"]
        local_p = None
        fname = os.path.basename(fpath.replace("\\", "/"))
        if is_smb_path(fpath):
            local_p = fetch_smb_file_cached(r["id"], fpath, conn)
        else:
            local_p = fpath if os.path.exists(fpath) else resolve_source_path(fpath)

        w, h, fsize, dt_str, lat, lon, exif_dict = extract_full_metadata(
            local_p,
            display_filename=fname,
            fallback_dt=r["date_taken"],
            fallback_lat=r["latitude"],
            fallback_lon=r["longitude"]
        )

        # If a demo sample image didn't have embedded camera EXIF tags, enrich with its album's camera profile
        if not is_smb_path(fpath) and exif_dict["camera_info"]["make_model"] == "—" and r["album_name"] in demo_camera_profiles:
            cam, lens, fl, ap, exp, iso, sw = demo_camera_profiles[r["album_name"]]
            exif_dict["camera_info"]["make_model"] = cam
            exif_dict["camera_info"]["lens"] = lens
            exif_dict["camera_info"]["focal_length"] = fl
            exif_dict["camera_info"]["aperture"] = ap
            exif_dict["camera_info"]["exposure"] = exp
            exif_dict["camera_info"]["iso_speed"] = iso
            exif_dict["camera_info"]["flash"] = "Off, Did not fire"
            exif_dict["processing_software"]["software"] = sw
            exif_dict["copyright_info"]["creator"] = "Memoria Demo Photographer"
            exif_dict["copyright_info"]["copyright"] = "© 2025 Memoria Vault Archive"
            exif_dict["copyright_info"]["right_holder"] = "Memoria Vault Archive"

        conn.execute(
            "UPDATE media SET width = ?, height = ?, exif_json = ? WHERE id = ?",
            (w or 1200, h or 800, json.dumps(exif_dict), r["id"])
        )
        updated = True

    if updated:
        conn.commit()


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    os.makedirs(SMB_CACHE_DIR, exist_ok=True)
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

    src_schema = c.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='sources_config'").fetchone()
    if src_schema and "path_location TEXT NOT NULL UNIQUE" in (src_schema[0] or ""):
        c.execute("ALTER TABLE sources_config RENAME TO sources_config_old;")
        c.execute("""
            CREATE TABLE sources_config (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                album_name TEXT NOT NULL,
                path_location TEXT NOT NULL,
                tags TEXT,
                last_synced DATETIME,
                smb_username TEXT DEFAULT '',
                smb_password TEXT DEFAULT '',
                sync_status TEXT DEFAULT ''
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
                last_synced DATETIME,
                smb_username TEXT DEFAULT '',
                smb_password TEXT DEFAULT '',
                sync_status TEXT DEFAULT ''
            );
        """)

    existing_cols = {r[1] for r in c.execute("PRAGMA table_info(sources_config)").fetchall()}
    if "smb_username" not in existing_cols:
        c.execute("ALTER TABLE sources_config ADD COLUMN smb_username TEXT DEFAULT '';")
    if "smb_password" not in existing_cols:
        c.execute("ALTER TABLE sources_config ADD COLUMN smb_password TEXT DEFAULT '';")
    if "sync_status" not in existing_cols:
        c.execute("ALTER TABLE sources_config ADD COLUMN sync_status TEXT DEFAULT '';")

    all_srcs = c.execute("SELECT id, album_name, path_location, smb_username FROM sources_config ORDER BY id ASC").fetchall()
    seen_smb_albums = {}
    for s in all_srcs:
        if is_smb_path(s["path_location"]):
            parsed = parse_smb_path(s["path_location"])
            norm_path = parsed[3] if parsed else s["path_location"]
            key = (s["album_name"].strip().lower(), norm_path.lower())
            if key in seen_smb_albums:
                c.execute("DELETE FROM sources_config WHERE id = ?", (s["id"],))
            else:
                seen_smb_albums[key] = s["id"]
                if s["path_location"] != norm_path:
                    c.execute("UPDATE sources_config SET path_location = ? WHERE id = ?", (norm_path, s["id"]))

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
                width INTEGER DEFAULT 0,
                height INTEGER DEFAULT 0,
                exif_json TEXT DEFAULT "",
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
                width INTEGER DEFAULT 0,
                height INTEGER DEFAULT 0,
                exif_json TEXT DEFAULT "",
                UNIQUE(album_name, file_path)
            );
        """)

    media_cols = {r[1] for r in c.execute("PRAGMA table_info(media)").fetchall()}
    if "width" not in media_cols:
        c.execute("ALTER TABLE media ADD COLUMN width INTEGER DEFAULT 0;")
    if "height" not in media_cols:
        c.execute("ALTER TABLE media ADD COLUMN height INTEGER DEFAULT 0;")
    if "exif_json" not in media_cols:
        c.execute("ALTER TABLE media ADD COLUMN exif_json TEXT DEFAULT '';")

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

    c.execute("DELETE FROM users WHERE username = 'admin' AND password_hash = 'admin'")
    c.execute("INSERT OR IGNORE INTO users (username, password_hash) VALUES (?, ?)", ("demo", "demo"))

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
            c.execute("INSERT INTO sources_config (album_name, path_location, tags, last_synced, sync_status) VALUES (?, ?, ?, datetime('now'), 'OK (Local Directory)')", (album, path, tags))

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
        c.execute("""
            UPDATE media
            SET source_id = (SELECT id FROM sources_config WHERE sources_config.album_name = media.album_name LIMIT 1)
            WHERE source_id IS NULL
        """)

    conn.commit()
    sync_all_sources(conn)
    backfill_media_exif(conn)
    conn.close()


def sync_all_sources(conn):
    sources = conn.execute("SELECT id, album_name, path_location, smb_username, smb_password FROM sources_config").fetchall()
    added_count = 0
    for src in sources:
        raw_p = src["path_location"]
        if is_smb_path(raw_p):
            ok, status_msg, smb_count = test_or_sync_smb_share(
                raw_p,
                smb_user=src["smb_username"] or "",
                smb_pass=src["smb_password"] or "",
                conn=conn,
                src_id=src["id"],
                album_name=src["album_name"]
            )
            conn.execute(
                "UPDATE sources_config SET last_synced = datetime('now'), sync_status = ? WHERE id = ?",
                (status_msg, src["id"])
            )
            if ok:
                added_count += smb_count
        else:
            resolved_p = resolve_source_path(raw_p)
            if resolved_p and os.path.exists(resolved_p):
                file_total = 0
                for root, _, files in os.walk(resolved_p):
                    for f in sorted(files):
                        if f.lower().endswith((".jpg", ".jpeg", ".png", ".webp")):
                            file_total += 1
                            full_p = os.path.join(root, f)
                            existing_meta = conn.execute(
                                "SELECT date_taken, latitude, longitude, caption, width, height, exif_json FROM media WHERE file_path = ? LIMIT 1",
                                (full_p,)
                            ).fetchone()
                            if existing_meta and existing_meta["width"] and existing_meta["exif_json"]:
                                dt = existing_meta["date_taken"]
                                lat = existing_meta["latitude"]
                                lon = existing_meta["longitude"]
                                cap = existing_meta["caption"] or ""
                                w = existing_meta["width"]
                                h = existing_meta["height"]
                                ex_json = existing_meta["exif_json"]
                            else:
                                fallback_dt = existing_meta["date_taken"] if existing_meta and existing_meta["date_taken"] else datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                fallback_lat = existing_meta["latitude"] if existing_meta else None
                                fallback_lon = existing_meta["longitude"] if existing_meta else None
                                cap = existing_meta["caption"] if existing_meta and existing_meta["caption"] else ""
                                w, h, _, dt, lat, lon, exif_dict = extract_full_metadata(
                                    full_p, display_filename=f, fallback_dt=fallback_dt, fallback_lat=fallback_lat, fallback_lon=fallback_lon
                                )
                                ex_json = json.dumps(exif_dict)

                            cur = conn.execute("""
                                INSERT OR IGNORE INTO media (source_id, album_name, file_path, file_type, date_taken, latitude, longitude, caption, width, height, exif_json)
                                VALUES (?, ?, ?, 'image', ?, ?, ?, ?, ?, ?, ?)
                            """, (src["id"], src["album_name"], full_p, dt, lat, lon, cap, w, h, ex_json))
                            if cur.rowcount > 0:
                                added_count += 1
                conn.execute(
                    "UPDATE sources_config SET last_synced = datetime('now'), sync_status = ? WHERE id = ?",
                    (f"OK ({file_total} local files indexed)", src["id"])
                )
            else:
                conn.execute(
                    "UPDATE sources_config SET last_synced = datetime('now'), sync_status = ? WHERE id = ?",
                    (f"Directory not found on container filesystem: {raw_p}", src["id"])
                )
    conn.commit()
    backfill_media_exif(conn)
    return added_count


def get_all_albums_summary(conn):
    album_dict = {}

    for r in conn.execute("SELECT id, album_name, path_location, last_synced, sync_status FROM sources_config ORDER BY album_name ASC").fetchall():
        name = (r["album_name"] or "").strip()
        if not name:
            continue
        album_dict[name] = {
            "album_name": name,
            "min_date": "",
            "max_date": "",
            "count": 0,
            "is_virtual": False,
            "is_smb": is_smb_path(r["path_location"]),
            "sync_status": r["sync_status"] or "",
            "source_id": r["id"]
        }

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
                "is_smb": False,
                "sync_status": "Virtual Album",
                "source_id": None
            }
        else:
            album_dict[name]["is_virtual"] = True

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
                "is_smb": False,
                "sync_status": "",
                "source_id": None
            }
        else:
            album_dict[name]["min_date"] = r["min_date"] or album_dict[name]["min_date"]
            album_dict[name]["max_date"] = r["max_date"] or album_dict[name]["max_date"]
            album_dict[name]["count"] = r["item_count"] or 0

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
                "is_smb": False,
                "sync_status": "Virtual Album",
                "source_id": None
            }
        else:
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

            query_sql = f"SELECT id, album_name, file_path, file_type, date_taken, latitude, longitude, caption, thumb_hash, width, height, exif_json FROM media WHERE {where_sql} ORDER BY {order_sql} LIMIT ? OFFSET ?"
            rows = conn.execute(query_sql, params + [limit, offset]).fetchall()

            items = []
            for r in rows:
                try:
                    exif_obj = json.loads(r["exif_json"]) if r["exif_json"] else {}
                except Exception:
                    exif_obj = {}
                items.append({
                    "id": r["id"],
                    "album_name": album if album else r["album_name"],
                    "origin_album": r["album_name"],
                    "file_type": r["file_type"],
                    "date_taken": r["date_taken"],
                    "latitude": r["latitude"],
                    "longitude": r["longitude"],
                    "caption": r["caption"],
                    "thumb_hash": r["thumb_hash"],
                    "width": r["width"] or 1200,
                    "height": r["height"] or 800,
                    "exif": exif_obj
                })
            conn.close()
            self.send_json({"total": total, "items": items})
            return

        elif path.startswith("/api/stream/file/"):
            media_id = path.split("/")[-1]
            conn = get_db()
            row = conn.execute("SELECT file_path, file_type FROM media WHERE id = ?", (media_id,)).fetchone()
            if not row:
                conn.close()
                self.send_error(404, "Media not found")
                return

            fpath = row["file_path"]
            if is_smb_path(fpath):
                cached_p = fetch_smb_file_cached(media_id, fpath, conn)
                conn.close()
                if cached_p and os.path.exists(cached_p):
                    fpath = cached_p
                else:
                    self.send_error(404, "Unable to stream SMB file")
                    return
            else:
                conn.close()
                if not os.path.exists(fpath):
                    fpath = resolve_source_path(fpath)

            if os.path.exists(fpath):
                mime = "image/jpeg" if fpath.lower().endswith((".jpg", ".jpeg")) else "image/png"
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
            rows = conn.execute(
                "SELECT id, album_name, path_location, tags, last_synced, smb_username, smb_password, sync_status FROM sources_config ORDER BY id ASC"
            ).fetchall()
            items = [
                {
                    "id": r["id"],
                    "album_name": r["album_name"],
                    "path_location": r["path_location"],
                    "tags": r["tags"],
                    "last_synced": r["last_synced"],
                    "smb_username": r["smb_username"] or "",
                    "smb_password": r["smb_password"] or "",
                    "sync_status": r["sync_status"] or ""
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
        <p class="text-xs text-zinc-400 mt-1">Status: Active & Operational (SQLite WAL Mode + Native SMB2/SMB3 Client + Pre-Indexed EXIF)</p>
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

        elif path == "/api/smb/test":
            path_loc = (payload.get("path_location") or "").strip()
            smb_user = (payload.get("smb_username") or "").strip()
            smb_pass = payload.get("smb_password") or ""
            if is_smb_path(path_loc):
                ok, msg, count = test_or_sync_smb_share(path_loc, smb_user, smb_pass)
                self.send_json({"ok": ok, "message": msg, "count": count}, status=200 if ok else 400)
            else:
                resolved = resolve_source_path(path_loc)
                if resolved and os.path.exists(resolved):
                    count = sum(
                        1 for _, _, files in os.walk(resolved)
                        for f in files if f.lower().endswith((".jpg", ".jpeg", ".png", ".webp"))
                    )
                    self.send_json({"ok": True, "message": f"Local folder accessible ({count} media files)", "count": count})
                else:
                    self.send_json({"ok": False, "message": f"Local path not found inside container: {path_loc}", "count": 0}, status=400)
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
                    smb_user = (cfg.get("smb_username") or "").strip()
                    smb_pass = cfg.get("smb_password") or ""
                    if not album_name or not path_loc:
                        continue
                    if is_smb_path(path_loc):
                        parsed_smb = parse_smb_path(path_loc)
                        if parsed_smb:
                            path_loc = parsed_smb[3]
                    cfg_id = cfg.get("id")
                    if cfg_id in existing_rows:
                        old_name = existing_rows[cfg_id]["album_name"]
                        conn.execute(
                            "UPDATE sources_config SET album_name = ?, path_location = ?, smb_username = ?, smb_password = ? WHERE id = ?",
                            (album_name, path_loc, smb_user, smb_pass, cfg_id)
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
                            "INSERT INTO sources_config (album_name, path_location, smb_username, smb_password, last_synced) VALUES (?, ?, ?, ?, datetime('now'))",
                            (album_name, path_loc, smb_user, smb_pass)
                        )
                        kept_ids.add(cur.lastrowid)
                        kept_album_names.add(album_name)

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
            if isinstance(payload, dict) and isinstance(payload.get("sources"), list):
                existing_rows = {
                    r["id"]: r for r in conn.execute("SELECT id, album_name, path_location FROM sources_config").fetchall()
                }
                kept_ids = set()
                for cfg in payload["sources"]:
                    album_name = (cfg.get("album_name") or "").strip()
                    path_loc = (cfg.get("path_location") or "").strip()
                    smb_user = (cfg.get("smb_username") or "").strip()
                    smb_pass = cfg.get("smb_password") or ""
                    if not album_name or not path_loc:
                        continue
                    if is_smb_path(path_loc):
                        parsed_smb = parse_smb_path(path_loc)
                        if parsed_smb:
                            path_loc = parsed_smb[3]
                    cfg_id = cfg.get("id")
                    if cfg_id in existing_rows:
                        old_name = existing_rows[cfg_id]["album_name"]
                        conn.execute(
                            "UPDATE sources_config SET album_name = ?, path_location = ?, smb_username = ?, smb_password = ? WHERE id = ?",
                            (album_name, path_loc, smb_user, smb_pass, cfg_id)
                        )
                        if old_name != album_name:
                            conn.execute(
                                "UPDATE media SET album_name = ? WHERE source_id = ? OR album_name = ?",
                                (album_name, cfg_id, old_name)
                            )
                        kept_ids.add(cfg_id)
                    else:
                        cur = conn.execute(
                            "INSERT INTO sources_config (album_name, path_location, smb_username, smb_password, last_synced) VALUES (?, ?, ?, ?, datetime('now'))",
                            (album_name, path_loc, smb_user, smb_pass)
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
                    f"SELECT id, album_name, file_type, date_taken, latitude, longitude, caption, thumb_hash, width, height, exif_json FROM media WHERE id IN ({placeholders}) ORDER BY date_taken DESC, id DESC",
                    mids
                ).fetchall()
                for r in media_rows:
                    try:
                        exif_obj = json.loads(r["exif_json"]) if r["exif_json"] else {}
                    except Exception:
                        exif_obj = {}
                    items.append({
                        "id": r["id"],
                        "album_name": row["album_name"],
                        "origin_album": r["album_name"],
                        "file_type": r["file_type"],
                        "date_taken": r["date_taken"],
                        "latitude": r["latitude"],
                        "longitude": r["longitude"],
                        "caption": r["caption"],
                        "thumb_hash": r["thumb_hash"],
                        "width": r["width"] or 1200,
                        "height": r["height"] or 800,
                        "exif": exif_obj
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
