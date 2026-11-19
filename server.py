import asyncio
import csv
import io
import json
import math
import os
import re
import socket
import sqlite3
import threading
import time
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from db import CLIENT_NETWORK, DB_PATH, DEPARTMENTS, DIVISIONS, GATEWAY_IP, YEARS, is_client_ip
from engine import engine

app = FastAPI(title="NetPlus Router Gateway — Cyber NOC", version="5.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
os.makedirs(STATIC_DIR, exist_ok=True)

latency_history: dict = {}
LATENCY_MAX_POINTS = 60


def measure_latency_once(label: str, host: str, port: int) -> int:
    try:
        start = time.time()
        s = socket.create_connection((host, port), timeout=5)
        s.close()
        return int((time.time() - start) * 1000)
    except Exception:
        return -1


def latency_monitor_loop():
    while True:
        try:
            with sqlite3.connect(DB_PATH, timeout=15.0) as conn:
                targets = conn.execute("SELECT label, host, port FROM latency_targets WHERE enabled = 1").fetchall()
        except Exception:
            targets = []

        for label, host, port in targets:
            ms = measure_latency_once(label, host, port)
            ts = datetime.now().strftime("%H:%M:%S")
            status = "ok" if ms != -1 and ms < 300 else ("slow" if ms != -1 else "down")
            point = {"time": ts, "ms": ms, "status": status}
            latency_history.setdefault(label, []).append(point)
            if len(latency_history[label]) > LATENCY_MAX_POINTS:
                latency_history[label] = latency_history[label][-LATENCY_MAX_POINTS:]

        time.sleep(30)


@app.on_event("startup")
def startup_event():
    threading.Thread(target=engine.start, daemon=True).start()
    threading.Thread(target=latency_monitor_loop, daemon=True).start()
    print("✨ NetPlus Router Gateway v5.0 Active — http://localhost:5000")


# ─── Pydantic Models ──────────────────────────────────────────
class BlockRequest(BaseModel):
    domain: str
    reason: Optional[str] = "Restricted domain"


class RenameRequest(BaseModel):
    name: str


class QuotaRequest(BaseModel):
    ip: str
    daily_mb_limit: int


class LatencyTargetRequest(BaseModel):
    label: str
    host: str
    port: int = 80


class RouterConfigRequest(BaseModel):
    router_ip: str = "192.168.137.2"
    username: str = "admin"
    password: str = "admin"
    enabled: bool = True


class StudentRegistrationRequest(BaseModel):
    token: str
    prn: str
    name: str
    department: str
    year: str
    division: str
    batch: str


class YearBatchRequest(BaseModel):
    year: str
    batch: str


class StudentAdminRegistrationRequest(BaseModel):
    mac_address: str
    prn: str
    name: str
    department: str
    year: str
    division: str
    batch: str


class StudentUpdateRequest(BaseModel):
    prn: str
    name: str
    department: str
    year: str
    division: str
    batch: str
    apply_to_history: bool = True
    date: Optional[str] = None
    session_id: Optional[int] = None


class ManualCheckInRequest(BaseModel):
    prn: str
    status: Optional[str] = "Present"
    session_id: Optional[int] = None


class SessionCreateRequest(BaseModel):
    session_type: str
    title: Optional[str] = ""
    date: Optional[str] = None
    time: Optional[str] = None
    year: str = ""
    division: str = ""
    batch: str = ""


# ─── Helpers ──────────────────────────────────────────────────
def calculate_device_liveness(last_seen_str):
    if not last_seen_str:
        return "Disconnected", 999999
    try:
        last_dt = datetime.strptime(last_seen_str, "%Y-%m-%d %H:%M:%S")
        diff = max(int((datetime.now() - last_dt).total_seconds()), 0)
        if diff <= 60:
            return "Online", diff
        if diff <= 300:
            return "Idle", diff
        return "Disconnected", diff
    except Exception:
        return "Disconnected", 999999


def group_logs_into_sessions(logs, gap_minutes=30):
    if not logs:
        return []
    sessions = []
    current = [logs[0]]
    for log in logs[1:]:
        try:
            prev_t = datetime.strptime(current[-1]["timestamp"], "%Y-%m-%d %H:%M:%S")
            curr_t = datetime.strptime(log["timestamp"], "%Y-%m-%d %H:%M:%S")
            if (curr_t - prev_t).total_seconds() > gap_minutes * 60:
                sessions.append(current)
                current = [log]
            else:
                current.append(log)
        except Exception:
            current.append(log)
    sessions.append(current)
    result = []
    for s in sessions:
        sites = {}
        total_bytes = 0
        for item in s:
            d = item.get("clean_site") or item.get("domain", "")
            sites[d] = sites.get(d, 0) + 1
            total_bytes += item.get("bytes", 0)
        top_sites = sorted(sites.items(), key=lambda x: -x[1])[:5]
        result.append({
            "start": s[0]["timestamp"],
            "end": s[-1]["timestamp"],
            "count": len(s),
            "total_bytes": total_bytes,
            "top_sites": [{"domain": k, "count": v} for k, v in top_sites],
        })
    return list(reversed(result))


# ─── Basic & Router Status Routes ─────────────────────────────
@app.get("/")
def get_index():
    idx = os.path.join(STATIC_DIR, "index.html")
    return FileResponse(idx) if os.path.exists(idx) else HTMLResponse("<h1>Starting…</h1>")


@app.get("/api/config")
def get_runtime_config():
    return {
        "mode": "router_gateway",
        "router_model": "TP-Link TL-WR740N (AP/Bridge)",
        "gateway_ip": GATEWAY_IP,
        "dns_port": engine.dns_server.port,
        "captive_http_port": engine.captive_http.port,
        "client_network": str(CLIENT_NETWORK),
    }


@app.get("/api/router/status")
def get_router_status():
    return engine.get_gateway_status()


@app.post("/api/router/config")
def update_router_config(req: RouterConfigRequest):
    engine.router_poller.configure(req.router_ip, req.username, req.password, req.enabled)
    ok = engine.router_poller.poll_once() if req.enabled else True
    return {"status": "ok" if ok else "unreachable", "router": engine.router_poller.get_snapshot()}


# ─── Stats ────────────────────────────────────────────────────
@app.get("/api/stats")
def get_stats(mode: str = "clean", date_from: Optional[str] = None, date_to: Optional[str] = None):
    with sqlite3.connect(DB_PATH, timeout=15.0) as conn:
        c = conn.cursor()
        conditions, params = [], []
        if mode == "clean":
            conditions.append("is_background = 0")
        if date_from:
            conditions.append("timestamp >= ?")
            params.append(f"{date_from} 00:00:00")
        if date_to:
            conditions.append("timestamp <= ?")
            params.append(f"{date_to} 23:59:59")
        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

        row = c.execute(f"SELECT COUNT(*), COALESCE(SUM(bytes_transferred),0) FROM access_logs {where}", params).fetchone()
        total_requests, total_bytes = row[0] or 0, row[1] or 0
        total_blocked = c.execute("SELECT COUNT(*) FROM access_logs WHERE status='Blocked'").fetchone()[0] or 0

        categories = {
            r[0]: r[1]
            for r in c.execute(f"SELECT category, COUNT(*) FROM access_logs {where} GROUP BY category ORDER BY COUNT(*) DESC", params).fetchall()
        }
        site_col = "clean_site" if mode == "clean" else "domain"
        top_domains = [
            {"domain": r[0], "count": r[1], "bytes": r[2]}
            for r in c.execute(
                f"SELECT {site_col}, COUNT(*), COALESCE(SUM(bytes_transferred),0) FROM access_logs {where} GROUP BY {site_col} ORDER BY COUNT(*) DESC LIMIT 10",
                params,
            ).fetchall()
        ]
        dev_rows = c.execute("SELECT ip, last_seen FROM devices").fetchall()

    online = sum(1 for r in dev_rows if calculate_device_liveness(r[1])[0] == "Online")
    return {
        "total_requests": total_requests,
        "total_bytes": total_bytes,
        "total_blocked": total_blocked,
        "active_devices": online,
        "total_devices": len(dev_rows),
        "categories": categories,
        "top_domains": top_domains,
    }


# ─── Local AI Traffic Analysis ────────────────────────────────
@app.get("/api/ai/analysis")
def get_ai_analysis(mode: str = "clean"):
    with sqlite3.connect(DB_PATH, timeout=15.0) as conn:
        c = conn.cursor()
        bg_filter = "AND is_background=0" if mode == "clean" else ""
        since = (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S")
        rows = c.execute(
            f"""
            SELECT client_ip, device_name, strftime('%Y-%m-%d', timestamp) AS day,
                   CAST(strftime('%H', timestamp) AS INTEGER) AS hour,
                   COUNT(*) AS requests, COALESCE(SUM(bytes_transferred),0) AS bytes
            FROM access_logs WHERE timestamp >= ? {bg_filter}
            GROUP BY client_ip, day, hour ORDER BY day DESC
            """,
            (since,),
        ).fetchall()
        device_count, log_count, _ = c.execute(
            f"SELECT COUNT(DISTINCT client_ip), COUNT(*), COALESCE(SUM(bytes_transferred),0) FROM access_logs WHERE timestamp >= ? {bg_filter}",
            (since,),
        ).fetchone()

        today = datetime.now().strftime("%Y-%m-%d")
        current_hour = datetime.now().hour
        buckets, current, names = {}, {}, {}
        for ip, name, day, hour, requests, byte_count in rows:
            names[ip] = name or ip
            if hour != current_hour:
                continue
            if day == today:
                current[ip] = (requests, byte_count)
            else:
                buckets.setdefault(ip, []).append(requests)

        anomalies = []
        for ip, (observed, byte_count) in current.items():
            history = buckets.get(ip, [])
            if len(history) < 3:
                continue
            mean = sum(history) / len(history)
            variance = sum((v - mean) ** 2 for v in history) / len(history)
            stddev = variance ** 0.5
            threshold = max(mean * 2, mean + 2 * stddev, mean + 5)
            if observed > threshold:
                anomalies.append({
                    "device": names[ip],
                    "ip": ip,
                    "observed": observed,
                    "expected": round(mean, 1),
                    "hour": f"{current_hour:02d}:00",
                    "bytes": byte_count,
                    "severity": "high" if observed > threshold * 2 else "medium",
                })
        anomalies.sort(key=lambda item: item["observed"] / max(item["expected"], 1), reverse=True)

        insights = []
        if log_count:
            top_category = c.execute(
                f"SELECT category, COUNT(*) FROM access_logs WHERE timestamp >= ? {bg_filter} GROUP BY category ORDER BY COUNT(*) DESC LIMIT 1",
                (since,),
            ).fetchone()
            peak_hour = c.execute(
                f"SELECT CAST(strftime('%H', timestamp) AS INTEGER), COUNT(*) FROM access_logs WHERE timestamp >= ? {bg_filter} GROUP BY 1 ORDER BY COUNT(*) DESC LIMIT 1",
                (since,),
            ).fetchone()
            if top_category:
                insights.append(f"Most common traffic category: {top_category[0]} ({top_category[1]:,} requests in 30 days).")
            if peak_hour:
                insights.append(f"Peak activity hour: {peak_hour[0]:02d}:00 ({peak_hour[1]:,} requests in 30 days).")
            if anomalies:
                insights.append(f"{len(anomalies)} device(s) have unusually high activity this hour compared with their own history.")
            else:
                insights.append("No unusual per-device activity detected for this hour.")
        else:
            insights.append("Waiting for device traffic. Analysis learns as the router gateway collects logs.")

    return {
        "model": "Per-device hourly baseline",
        "training_days": 30,
        "training_requests": log_count,
        "devices_trained": device_count,
        "trained_days_required": 3,
        "anomalies": anomalies,
        "insights": insights,
        "privacy": "Analysis runs locally on this gateway; raw browsing history is not sent to an external AI service.",
    }


# ─── Academic Options ─────────────────────────────────────────
def _get_year_batches():
    with sqlite3.connect(DB_PATH, timeout=15.0) as conn:
        rows = conn.execute("SELECT year, batch FROM year_batches ORDER BY year, batch COLLATE NOCASE").fetchall()
    result = {y["value"]: [] for y in YEARS}
    for year, batch in rows:
        result.setdefault(year, []).append(batch)
    return result


def _validate_student_fields(prn, name, department, year, division, batch):
    if not 2 <= len(prn) <= 40:
        raise HTTPException(422, "Enter a valid PRN (2–40 characters).")
    if not 2 <= len(name) <= 100:
        raise HTTPException(422, "Enter your name (2–100 characters).")
    if department not in DEPARTMENTS:
        raise HTTPException(422, "Select a department from the list.")
    if year not in {y["value"] for y in YEARS}:
        raise HTTPException(422, "Select a year from the list.")
    if division not in DIVISIONS:
        raise HTTPException(422, "Select a division from the list.")
    if batch not in _get_year_batches().get(year, []):
        raise HTTPException(422, f"Select a valid batch for {year}.")


@app.get("/api/academic/options")
def get_academic_options():
    return {
        "departments": DEPARTMENTS,
        "years": YEARS,
        "divisions": DIVISIONS,
        "batches": _get_year_batches(),
    }


@app.post("/api/academic/batches")
def add_year_batch(req: YearBatchRequest):
    year, batch = req.year.strip(), req.batch.strip()
    if year not in {y["value"] for y in YEARS}:
        raise HTTPException(422, "Unknown year.")
    if not 1 <= len(batch) <= 30:
        raise HTTPException(422, "Batch name must be 1–30 characters.")
    try:
        with sqlite3.connect(DB_PATH, timeout=15.0) as conn:
            conn.execute("INSERT INTO year_batches (year, batch) VALUES (?, ?)", (year, batch))
    except sqlite3.IntegrityError:
        raise HTTPException(409, f"Batch '{batch}' already exists for {year}.")
    return {"status": "ok", "message": f"Batch '{batch}' added to {year}."}


@app.delete("/api/academic/batches/{year}/{batch}")
def delete_year_batch(year: str, batch: str):
    with sqlite3.connect(DB_PATH, timeout=15.0) as conn:
        in_use = conn.execute("SELECT COUNT(*) FROM students WHERE year=? AND batch=?", (year, batch)).fetchone()[0]
        if in_use:
            raise HTTPException(409, f"{in_use} student(s) are in this batch. Move them before deleting it.")
        conn.execute("DELETE FROM year_batches WHERE year=? AND batch=?", (year, batch))
    return {"status": "ok", "message": f"Batch '{batch}' removed from {year}."}


# ─── Attendance & Student Registration ────────────────────────
@app.post("/api/attendance/prompts/reset")
def reset_join_prompts(device_key: Optional[str] = None):
    engine.reset_prompts(device_key)
    return {"status": "ok", "message": "Join prompt re-enabled." if device_key else "Join prompt re-enabled for all devices."}


@app.get("/attendance/register")
def attendance_registration_page():
    page = os.path.join(STATIC_DIR, "attendance.html")
    return FileResponse(page) if os.path.exists(page) else HTMLResponse("Registration page unavailable", status_code=503)


@app.post("/api/attendance/register")
def register_attendance_student(req: StudentRegistrationRequest):
    ip = engine.get_registration_ip(req.token)
    if not ip:
        raise HTTPException(400, "This registration link has expired. Open a plain HTTP website again to get a new one.")
    mac = engine.get_mac_for_ip(ip)
    if not mac:
        raise HTTPException(409, "Could not read this device's MAC address yet. Reconnect to the router Wi-Fi and try again.")

    prn, name = req.prn.strip(), req.name.strip()
    department, year = req.department.strip(), req.year.strip()
    division, batch = req.division.strip(), req.batch.strip()
    _validate_student_fields(prn, name, department, year, division, batch)

    try:
        with sqlite3.connect(DB_PATH, timeout=15.0) as conn:
            conn.execute(
                "INSERT INTO students (mac_address, prn, name, department, year, division, batch, registered_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (mac, prn, name, department, year, division, batch, datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            )
    except sqlite3.IntegrityError:
        raise HTTPException(409, "This device or PRN is already registered. Contact the administrator if your details need correction.")

    engine.consume_registration_token(req.token)
    student = {"mac_address": mac, "prn": prn, "name": name, "batch": batch,
               "department": department, "year": year, "division": division}
    marked = engine.record_attendance(student, ip=ip)
    return {
        "status": "ok",
        "name": name,
        "prn": prn,
        "batch": batch,
        "department": department,
        "year": year,
        "division": division,
        "attendance_marked": marked,
        "attendance_date": datetime.now().strftime("%Y-%m-%d"),
    }


def _session_scope_sql(session_id: Optional[str], date: Optional[str], alias: str = "a"):
    col = f"{alias}." if alias else ""
    if session_id and session_id not in ("all", "legacy"):
        try:
            return f" {col}session_id = ?", [int(session_id)]
        except ValueError:
            raise HTTPException(400, "Invalid session id.")
    if session_id == "legacy":
        return f" {col}session_id IS NULL AND {col}attendance_date = ?", [date]
    return f" {col}attendance_date = ?", [date]


@app.get("/api/attendance")
def get_attendance(
    date: Optional[str] = None,
    batch: Optional[str] = None,
    search: Optional[str] = None,
    year: Optional[str] = None,
    department: Optional[str] = None,
    division: Optional[str] = None,
    session_id: Optional[str] = None,
):
    attendance_date = date or datetime.now().strftime("%Y-%m-%d")
    try:
        datetime.strptime(attendance_date, "%Y-%m-%d")
    except ValueError:
        raise HTTPException(400, "Date must use YYYY-MM-DD format.")

    with sqlite3.connect(DB_PATH, timeout=15.0) as conn:
        query = """
            SELECT a.id, a.prn, a.student_name, a.batch, a.mac_address,
                   COALESCE(a.ip_address, ''), a.attendance_date, a.first_seen, a.last_seen,
                   a.connection_count, COALESCE(a.status, 'Present'),
                   COALESCE(a.department, ''), COALESCE(a.year, ''), COALESCE(a.division, ''),
                   a.session_id, COALESCE(s.session_type, ''), COALESCE(s.title, '')
            FROM attendance a
            LEFT JOIN sessions s ON s.id = a.session_id
            WHERE"""
        scope_sql, params = _session_scope_sql(session_id, attendance_date)
        query += scope_sql
        for col, val in (("a.batch", batch), ("a.year", year), ("a.department", department), ("a.division", division)):
            if val and val != "All":
                query += f" AND {col} = ?"
                params.append(val)
        if search:
            query += " AND (a.prn LIKE ? OR a.student_name LIKE ? OR a.mac_address LIKE ?)"
            s_ = f"%{search.strip()}%"
            params.extend([s_, s_, s_])
        query += " ORDER BY a.first_seen DESC"
        rows = conn.execute(query, params).fetchall()

    results = []
    now = datetime.now()
    for r in rows:
        aid, prn, name, bat, mac, ip, adate, first_s, last_s, count, status, dept, yr, div, sid, stype, stitle = r
        dur_mins, is_online = 0, False
        try:
            dt1 = datetime.strptime(first_s, "%Y-%m-%d %H:%M:%S")
            dt2 = datetime.strptime(last_s, "%Y-%m-%d %H:%M:%S")
            dur_mins = max(int((dt2 - dt1).total_seconds() / 60), 0)
            is_online = (now - dt2).total_seconds() <= 90
        except Exception:
            pass
        dur_str = f"{dur_mins // 60}h {dur_mins % 60}m" if dur_mins >= 60 else f"{dur_mins}m"
        results.append({
            "id": aid, "prn": prn, "name": name, "batch": bat, "department": dept, "year": yr,
            "division": div, "mac_address": mac, "ip_address": ip, "date": adate,
            "session_id": sid, "session_type": stype, "session_title": stitle,
            "first_seen": first_s, "last_seen": last_s, "duration_minutes": dur_mins,
            "duration_formatted": dur_str, "connections": count, "status": status, "is_online": is_online,
        })
    return results


@app.get("/api/attendance/stats")
def get_attendance_stats(date: Optional[str] = None, session_id: Optional[str] = None):
    attendance_date = date or datetime.now().strftime("%Y-%m-%d")
    eligible_label = "registered"
    with sqlite3.connect(DB_PATH, timeout=15.0) as conn:
        total_students = conn.execute("SELECT COUNT(*) FROM students").fetchone()[0] or 0
        if session_id and session_id not in ("all", "legacy"):
            sess = conn.execute("SELECT year, division, batch FROM sessions WHERE id=?", (session_id,)).fetchone()
            if sess:
                q, p = "SELECT COUNT(*) FROM students WHERE 1=1", []
                for col, val in zip(("year", "division", "batch"), sess):
                    if val:
                        q += f" AND {col}=?"
                        p.append(val)
                total_students = conn.execute(q, p).fetchone()[0] or 0
                eligible_label = "eligible"
        scope_sql, params = _session_scope_sql(session_id, attendance_date, alias="")
        present_count = conn.execute(f"SELECT COUNT(DISTINCT mac_address) FROM attendance WHERE{scope_sql}", params).fetchone()[0] or 0
        batches = conn.execute("SELECT DISTINCT batch FROM students ORDER BY batch").fetchall()
        batch_list = [b[0] for b in batches if b[0]]
        batches_by_year = _get_year_batches()

        active_now = 0
        today_att = conn.execute(f"SELECT last_seen FROM attendance WHERE{scope_sql}", params).fetchall()
        now = datetime.now()
        for r in today_att:
            try:
                if (now - datetime.strptime(r[0], "%Y-%m-%d %H:%M:%S")).total_seconds() <= 90:
                    active_now += 1
            except Exception:
                pass

    rate = round((present_count / total_students * 100), 1) if total_students > 0 else 0
    return {
        "date": attendance_date,
        "session_id": session_id,
        "total_registered": total_students,
        "total_label": eligible_label,
        "present_today": present_count,
        "active_now": active_now,
        "attendance_rate": rate,
        "batches": batch_list,
        "batches_by_year": batches_by_year,
    }


SESSION_TYPES = ["Lab", "Theory"]
_SESSION_COLS = "id, session_type, title, session_date, start_time, year, division, batch, status, started_at, ended_at"


def _session_row_to_dict(r, present=0):
    return {
        "id": r[0], "session_type": r[1], "title": r[2], "date": r[3], "start_time": r[4],
        "year": r[5], "division": r[6], "batch": r[7], "status": r[8],
        "started_at": r[9], "ended_at": r[10], "present_count": present,
    }


@app.get("/api/attendance/sessions")
def list_sessions(date: Optional[str] = None, limit: int = 100):
    with sqlite3.connect(DB_PATH, timeout=15.0) as conn:
        q, p = f"SELECT {_SESSION_COLS} FROM sessions", []
        if date:
            q += " WHERE session_date = ?"
            p.append(date)
        q += " ORDER BY id DESC LIMIT ?"
        p.append(max(1, min(limit, 500)))
        rows = conn.execute(q, p).fetchall()
        counts = dict(conn.execute("SELECT session_id, COUNT(*) FROM attendance WHERE session_id IS NOT NULL GROUP BY session_id").fetchall())
        legacy = conn.execute("SELECT COUNT(*) FROM attendance WHERE session_id IS NULL AND attendance_date=?", (date,)).fetchone()[0] if date else 0
    return {"sessions": [_session_row_to_dict(r, counts.get(r[0], 0)) for r in rows], "legacy_count": legacy}


@app.get("/api/attendance/sessions/active")
def get_active_session():
    with sqlite3.connect(DB_PATH, timeout=15.0) as conn:
        r = conn.execute(f"SELECT {_SESSION_COLS} FROM sessions WHERE status='active' ORDER BY id DESC LIMIT 1").fetchone()
        if not r:
            return {"active": None}
        present = conn.execute("SELECT COUNT(*) FROM attendance WHERE session_id=?", (r[0],)).fetchone()[0]
    return {"active": _session_row_to_dict(r, present)}


@app.post("/api/attendance/sessions")
def create_session(req: SessionCreateRequest):
    stype = (req.session_type or "").strip().title()
    if stype not in SESSION_TYPES:
        raise HTTPException(422, "Session type must be Lab or Theory.")
    title = (req.title or "").strip()
    if len(title) > 100:
        raise HTTPException(422, "Title can be at most 100 characters.")
    date_str = (req.date or datetime.now().strftime("%Y-%m-%d")).strip()
    time_str = (req.time or datetime.now().strftime("%H:%M")).strip()
    try:
        datetime.strptime(date_str, "%Y-%m-%d")
        datetime.strptime(time_str[:5], "%H:%M")
    except ValueError:
        raise HTTPException(400, "Use YYYY-MM-DD for the date and HH:MM for the time.")
    time_str = time_str[:5]

    year, division, batch = (req.year or "").strip(), (req.division or "").strip(), (req.batch or "").strip()
    if year and year not in {y["value"] for y in YEARS}:
        raise HTTPException(422, "Select a valid year.")
    if division and division not in DIVISIONS:
        raise HTTPException(422, "Select a valid division.")
    if batch:
        valid = _get_year_batches().get(year, []) if year else [b for lst in _get_year_batches().values() for b in lst]
        if batch not in valid:
            raise HTTPException(422, "Select a valid batch" + (f" for {year}." if year else "."))

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with sqlite3.connect(DB_PATH, timeout=15.0) as conn:
        running = conn.execute("SELECT id, session_type, title FROM sessions WHERE status='active' LIMIT 1").fetchone()
        if running:
            label = f"{running[1]}{' – ' + running[2] if running[2] else ''}"
            raise HTTPException(409, f"Session #{running[0]} ({label}) is still running. End it before starting a new one.")
        cur = conn.execute(
            "INSERT INTO sessions (session_type, title, session_date, start_time, year, division, batch, status, started_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?)",
            (stype, title, date_str, time_str, year, division, batch, now_str),
        )
        sid = cur.lastrowid
        r = conn.execute(f"SELECT {_SESSION_COLS} FROM sessions WHERE id=?", (sid,)).fetchone()
    engine.broadcast_event({"type": "SESSION_CHANGED", "action": "started", "session_id": sid})
    return {"status": "ok", "message": f"{stype} session started.", "session": _session_row_to_dict(r)}


@app.post("/api/attendance/sessions/{session_id}/end")
def end_session(session_id: int):
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with sqlite3.connect(DB_PATH, timeout=15.0) as conn:
        r = conn.execute("SELECT status FROM sessions WHERE id=?", (session_id,)).fetchone()
        if not r:
            raise HTTPException(404, "Session not found.")
        if r[0] != "active":
            raise HTTPException(409, "This session has already ended.")
        conn.execute("UPDATE sessions SET status='ended', ended_at=? WHERE id=?", (now_str, session_id))
        present = conn.execute("SELECT COUNT(*) FROM attendance WHERE session_id=?", (session_id,)).fetchone()[0]
    engine.broadcast_event({"type": "SESSION_CHANGED", "action": "ended", "session_id": session_id})
    return {"status": "ok", "message": f"Session ended — {present} student(s) marked present.", "present_count": present}


@app.delete("/api/attendance/sessions/{session_id}")
def delete_session(session_id: int):
    with sqlite3.connect(DB_PATH, timeout=15.0) as conn:
        r = conn.execute("SELECT status FROM sessions WHERE id=?", (session_id,)).fetchone()
        if not r:
            raise HTTPException(404, "Session not found.")
        if r[0] == "active":
            raise HTTPException(409, "End the session before deleting it.")
        conn.execute("DELETE FROM attendance WHERE session_id=?", (session_id,))
        conn.execute("DELETE FROM sessions WHERE id=?", (session_id,))
    engine.broadcast_event({"type": "SESSION_CHANGED", "action": "deleted", "session_id": session_id})
    return {"status": "ok", "message": "Session and its attendance records deleted."}


@app.post("/api/attendance/checkin")
def manual_attendance_checkin(req: ManualCheckInRequest):
    prn = req.prn.strip()
    status = req.status or "Present"
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with sqlite3.connect(DB_PATH, timeout=15.0) as conn:
        if req.session_id is not None:
            sess = conn.execute("SELECT id, session_date, status FROM sessions WHERE id=?", (req.session_id,)).fetchone()
            if not sess:
                raise HTTPException(404, "Session not found.")
        else:
            sess = conn.execute("SELECT id, session_date, status FROM sessions WHERE status='active' ORDER BY id DESC LIMIT 1").fetchone()
            if not sess:
                raise HTTPException(409, "No session is running. Start a session first.")
        sid, date_str, _ = sess
        stu = conn.execute(
            "SELECT mac_address, prn, name, batch, COALESCE(department,''), COALESCE(year,''), COALESCE(division,'') FROM students WHERE prn=?",
            (prn,),
        ).fetchone()
        if not stu:
            raise HTTPException(404, f"Student with PRN '{prn}' not found.")
        mac, prn, name, batch, dept, yr, div = stu
        conn.execute(
            """
            INSERT INTO attendance
                (mac_address, prn, student_name, batch, department, year, division, attendance_date, first_seen, last_seen, connection_count, status, session_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
            ON CONFLICT(mac_address, session_id) DO UPDATE SET
                status = excluded.status,
                last_seen = excluded.last_seen,
                connection_count = attendance.connection_count + 1
            """,
            (mac, prn, name, batch, dept, yr, div, date_str, now_str, now_str, status, sid),
        )
    return {"status": "ok", "message": f"Attendance marked for {name} ({prn}) in session #{sid} as {status}."}


@app.delete("/api/attendance/{record_id}")
def delete_attendance_record(record_id: int):
    with sqlite3.connect(DB_PATH, timeout=15.0) as conn:
        conn.execute("DELETE FROM attendance WHERE id=?", (record_id,))
    return {"status": "ok", "message": "Attendance record deleted."}


# ─── Connected Devices & Students ─────────────────────────────
@app.get("/api/connected-devices")
def get_connected_devices():
    engine.scan_connected_devices()
    with sqlite3.connect(DB_PATH, timeout=15.0) as conn:
        rows = conn.execute(
            "SELECT d.ip, d.custom_name, d.auto_name, d.device_type, d.first_seen, d.last_seen, COALESCE(d.mac_address, '') "
            "FROM devices d ORDER BY d.last_seen DESC"
        ).fetchall()
        student_map = {
            r[0].lower(): {"prn": r[1], "name": r[2], "batch": r[3], "department": r[4], "year": r[5], "division": r[6]}
            for r in conn.execute(
                "SELECT mac_address, prn, name, batch, COALESCE(department,''), COALESCE(year,''), COALESCE(division,'') FROM students"
            ).fetchall()
        }

    wlan_macs = {s["mac"]: s for s in engine.router_poller.get_snapshot().get("wireless_stations", [])}
    result = []
    for ip, cname, aname, dtype, first_s, last_s, mac in rows:
        liveness, sec = calculate_device_liveness(last_s)
        stu = student_map.get(mac.lower()) if mac else None
        result.append({
            "ip": ip,
            "mac": mac,
            "name": cname or aname,
            "device_type": dtype or "mobile",
            "first_seen": first_s,
            "last_seen": last_s,
            "liveness": liveness,
            "seconds_ago": sec,
            "is_online": liveness == "Online",
            "student": stu,
            "wireless_stats": wlan_macs.get(mac.lower()) if mac else None,
        })
    return result


@app.get("/api/students")
def get_students():
    with sqlite3.connect(DB_PATH, timeout=15.0) as conn:
        rows = conn.execute(
            "SELECT prn, name, batch, mac_address, registered_at, COALESCE(department,''), COALESCE(year,''), COALESCE(division,'') "
            "FROM students ORDER BY name COLLATE NOCASE"
        ).fetchall()
    return [
        {"prn": r[0], "name": r[1], "batch": r[2], "mac_address": r[3], "registered_at": r[4],
         "department": r[5], "year": r[6], "division": r[7]}
        for r in rows
    ]


@app.post("/api/students")
def admin_register_student(req: StudentAdminRegistrationRequest):
    mac = req.mac_address.strip().replace("-", ":").lower()
    if not re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", mac):
        raise HTTPException(422, "Enter a MAC address in the format AA:BB:CC:DD:EE:FF.")
    prn, name = req.prn.strip(), req.name.strip()
    department, year = req.department.strip(), req.year.strip()
    division, batch = req.division.strip(), req.batch.strip()
    _validate_student_fields(prn, name, department, year, division, batch)

    try:
        with sqlite3.connect(DB_PATH, timeout=15.0) as conn:
            conn.execute(
                """
                INSERT INTO students (mac_address, prn, name, department, year, division, batch, registered_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(mac_address) DO UPDATE SET
                    prn=excluded.prn, name=excluded.name, department=excluded.department,
                    year=excluded.year, division=excluded.division, batch=excluded.batch,
                    registered_at=excluded.registered_at
                """,
                (mac, prn, name, department, year, division, batch, datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            )
    except sqlite3.IntegrityError:
        raise HTTPException(409, "That PRN is already registered to a different MAC address.")

    student_obj = {"mac_address": mac, "prn": prn, "name": name, "batch": batch,
                   "department": department, "year": year, "division": division}
    marked = engine.record_attendance(student_obj)
    note = "Attendance marked in the active session." if marked else "No matching active session, so no attendance was marked."
    return {"status": "ok", "message": f"{name} ({prn}) registered for {mac}. {note}"}


@app.put("/api/students/{mac}")
def update_student(mac: str, req: StudentUpdateRequest):
    mac = mac.strip().replace("-", ":").lower()
    if not re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", mac):
        raise HTTPException(422, "Invalid MAC address.")
    prn, name = req.prn.strip(), req.name.strip()
    department, year = req.department.strip(), req.year.strip()
    division, batch = req.division.strip(), req.batch.strip()
    _validate_student_fields(prn, name, department, year, division, batch)

    att_date = req.date or datetime.now().strftime("%Y-%m-%d")
    try:
        datetime.strptime(att_date, "%Y-%m-%d")
    except ValueError:
        raise HTTPException(400, "Date must use YYYY-MM-DD format.")

    try:
        with sqlite3.connect(DB_PATH, timeout=15.0) as conn:
            clash = conn.execute("SELECT mac_address FROM students WHERE prn=? AND mac_address!=?", (prn, mac)).fetchone()
            if clash:
                raise HTTPException(409, f"PRN '{prn}' already belongs to another student ({clash[0]}).")
            if conn.execute("SELECT 1 FROM students WHERE mac_address=?", (mac,)).fetchone():
                conn.execute(
                    "UPDATE students SET prn=?, name=?, department=?, year=?, division=?, batch=? WHERE mac_address=?",
                    (prn, name, department, year, division, batch, mac),
                )
            else:
                conn.execute(
                    "INSERT INTO students (mac_address, prn, name, department, year, division, batch, registered_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (mac, prn, name, department, year, division, batch, datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                )

            if req.apply_to_history:
                cur = conn.execute(
                    "UPDATE attendance SET prn=?, student_name=?, department=?, year=?, division=?, batch=? WHERE mac_address=?",
                    (prn, name, department, year, division, batch, mac),
                )
            elif req.session_id is not None:
                cur = conn.execute(
                    "UPDATE attendance SET prn=?, student_name=?, department=?, year=?, division=?, batch=? WHERE mac_address=? AND session_id=?",
                    (prn, name, department, year, division, batch, mac, req.session_id),
                )
            else:
                cur = conn.execute(
                    "UPDATE attendance SET prn=?, student_name=?, department=?, year=?, division=?, batch=? WHERE mac_address=? AND attendance_date=?",
                    (prn, name, department, year, division, batch, mac, att_date),
                )
            updated_rows = cur.rowcount

            new_dev_name = f"{name}'s Device"
            ips = [r[0] for r in conn.execute("SELECT ip FROM devices WHERE mac_address=? AND name_source='student' AND COALESCE(custom_name,'')=''", (mac,))]
            for ip in ips:
                conn.execute("UPDATE devices SET auto_name=? WHERE ip=?", (new_dev_name, ip))
                conn.execute("UPDATE access_logs SET device_name=? WHERE client_ip=?", (new_dev_name, ip))
    except sqlite3.IntegrityError:
        raise HTTPException(409, f"PRN '{prn}' is already in use.")

    return {"status": "ok", "message": f"{name} ({prn}) updated — {updated_rows} attendance record(s) refreshed."}


@app.delete("/api/students/{prn}")
def delete_student(prn: str):
    with sqlite3.connect(DB_PATH, timeout=15.0) as conn:
        conn.execute("DELETE FROM students WHERE prn=?", (prn.strip(),))
    return {"status": "ok", "message": f"Student with PRN {prn} deleted."}


# ─── ML Dataset Export ────────────────────────────────────────
CATEGORY_ENCODING = {
    "Academic & Learning": 1, "Entertainment & Social": 2, "Gaming & Arcade": 3,
    "Search & Knowledge": 4, "Messaging & Collab": 5, "Cloud & Infrastructure": 6,
    "Proxy & Bypass": 7, "Shopping & Services": 8, "General Web": 9,
}
DEVICE_TYPE_ENCODING = {"desktop": 1, "mobile": 2, "tablet": 3, "laptop": 4}
METHOD_ENCODING = {"GET": 1, "POST": 2, "CONNECT": 3, "PUT": 4, "DELETE": 5, "HEAD": 6, "DNS": 7, "HTTPS-SNI": 8, "FLOW": 9}
RISK_ENCODING = {"Normal": 0, "Low": 1, "Policy Violation": 2, "Restricted Gaming": 2, "Quota Exceeded": 2, "Bypass Attempt": 3}


@app.get("/api/export/schema")
def get_export_schema():
    return {
        "datasets": {
            "traffic_features": {
                "name": "Network Traffic ML Feature Matrix",
                "description": "Pre-engineered numerical and categorical features extracted from router gateway access logs.",
                "attributes": [
                    {"name": "log_id", "type": "int", "role": "identifier", "description": "Sequential entry ID"},
                    {"name": "timestamp", "type": "string", "role": "temporal", "description": "Event timestamp"},
                    {"name": "epoch_time", "type": "float", "role": "temporal", "description": "Unix timestamp"},
                    {"name": "hour_of_day", "type": "int", "role": "cyclical", "description": "Hour (0-23)"},
                    {"name": "day_of_week", "type": "int", "role": "cyclical", "description": "Day (0=Mon..6=Sun)"},
                    {"name": "client_ip", "type": "string", "role": "categorical", "description": "Client IP"},
                    {"name": "client_mac", "type": "string", "role": "categorical", "description": "Client MAC"},
                    {"name": "domain", "type": "string", "role": "text", "description": "Target hostname"},
                    {"name": "clean_site", "type": "string", "role": "categorical", "description": "Root brand"},
                    {"name": "category_code", "type": "int", "role": "target", "description": "Encoded category"},
                    {"name": "bytes_transferred", "type": "int", "role": "continuous", "description": "Bytes transferred"},
                    {"name": "is_anomaly", "type": "binary", "role": "target", "description": "1 if blocked/risky, else 0"},
                ],
            },
            "device_profiles": {
                "name": "Device Behavioral Feature Vectors",
                "description": "Aggregated per-device statistics for clustering and profiling.",
                "attributes": [
                    {"name": "client_ip", "type": "string", "role": "identifier", "description": "Device IP"},
                    {"name": "client_mac", "type": "string", "role": "identifier", "description": "Device MAC"},
                    {"name": "total_visits", "type": "int", "role": "continuous", "description": "Total visits"},
                    {"name": "total_mb_used", "type": "float", "role": "continuous", "description": "Total MB used"},
                    {"name": "threat_level", "type": "string", "role": "target", "description": "Low/Medium/High"},
                ],
            },
            "attendance_ml": {
                "name": "Student Attendance & Network Engagement Dataset",
                "description": "Attendance timestamps and network liveness metrics.",
                "attributes": [
                    {"name": "attendance_id", "type": "int", "role": "identifier", "description": "Record ID"},
                    {"name": "prn", "type": "string", "role": "identifier", "description": "Student PRN"},
                    {"name": "duration_minutes", "type": "int", "role": "continuous", "description": "Session duration"},
                    {"name": "is_punctual", "type": "binary", "role": "target", "description": "1 if before 09:30 AM"},
                ],
            },
        }
    }


@app.get("/api/export/ai-dataset")
def export_ai_dataset(
    type: str = "traffic_features",
    format: str = "csv",
    limit: int = 5000,
    mode: str = "clean",
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    session_id: Optional[int] = None,
):
    with sqlite3.connect(DB_PATH, timeout=15.0) as conn:
        c = conn.cursor()
        mac_to_student = {r[0].lower(): {"prn": r[1], "name": r[2], "batch": r[3]} for r in c.execute("SELECT mac_address, prn, name, batch FROM students").fetchall()}
        ip_to_mac = {r[0]: r[1].lower() for r in c.execute("SELECT ip, COALESCE(mac_address,'') FROM devices").fetchall()}

        records = []
        filename_prefix = f"netplus_{type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        if type in ("traffic_features", "raw_logs"):
            conditions, params = [], []
            if mode == "clean" and type == "traffic_features":
                conditions.append("is_background = 0")
            if start_date:
                conditions.append("timestamp >= ?")
                params.append(f"{start_date} 00:00:00")
            if end_date:
                conditions.append("timestamp <= ?")
                params.append(f"{end_date} 23:59:59")
            where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
            lim_clause = f"LIMIT {limit}" if limit and limit > 0 else ""
            rows = c.execute(
                f"SELECT id, timestamp, client_ip, device_name, device_type, domain, clean_site, "
                f"is_background, category, method, bytes_transferred, status, risk_flag, user_agent "
                f"FROM access_logs {where} ORDER BY id DESC {lim_clause}",
                params,
            ).fetchall()

            for r in rows:
                lid, ts, ip, dev_name, dev_type, dom, csite, is_bg, cat, meth, b_trans, stat, r_flag, ua = r
                mac = ip_to_mac.get(ip, "")
                stu = mac_to_student.get(mac, {}) if mac else {}
                epoch, hour, dow, is_wknd, is_acad_hours = 0.0, 0, 0, 0, 0
                try:
                    dt = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
                    epoch, hour, dow = dt.timestamp(), dt.hour, dt.weekday()
                    is_wknd = 1 if dow >= 5 else 0
                    is_acad_hours = 1 if (dow < 5 and 9 <= hour <= 17) else 0
                except Exception:
                    pass
                bytes_val = b_trans or 0
                meth_upper = (meth or "GET").upper()
                dev_type_str = (dev_type or "mobile").lower()
                r_score = max(RISK_ENCODING.get(r_flag, 0), 2 if stat == "Blocked" else 0)
                if type == "traffic_features":
                    records.append({
                        "log_id": lid, "timestamp": ts, "epoch_time": epoch, "hour_of_day": hour,
                        "day_of_week": dow, "is_weekend": is_wknd, "is_academic_hours": is_acad_hours,
                        "client_ip": ip, "client_mac": mac or "UNKNOWN", "device_name": dev_name,
                        "device_type": dev_type_str, "device_type_code": DEVICE_TYPE_ENCODING.get(dev_type_str, 2),
                        "student_prn": stu.get("prn", "UNREGISTERED"), "student_batch": stu.get("batch", "NONE"),
                        "domain": dom, "clean_site": csite or dom, "domain_length": len(dom or ""),
                        "subdomain_count": (dom or "").count("."), "method": meth_upper,
                        "method_code": METHOD_ENCODING.get(meth_upper, 0), "category": cat,
                        "category_code": CATEGORY_ENCODING.get(cat, 9), "is_background": is_bg,
                        "bytes_transferred": bytes_val, "log_bytes": round(math.log1p(bytes_val), 4),
                        "status": stat, "status_code": 1 if stat == "Allowed" else 0,
                        "risk_flag": r_flag, "risk_score": r_score,
                        "is_anomaly": 1 if (r_score > 0 or stat == "Blocked") else 0,
                    })
                else:
                    records.append({
                        "id": lid, "timestamp": ts, "client_ip": ip, "device_name": dev_name,
                        "device_type": dev_type, "domain": dom, "clean_site": csite,
                        "is_background": is_bg, "category": cat, "method": meth,
                        "bytes_transferred": bytes_val, "status": stat, "risk_flag": r_flag, "user_agent": ua,
                    })
        elif type == "device_profiles":
            dev_rows = c.execute(
                """
                SELECT d.ip, COALESCE(NULLIF(d.custom_name,''), d.auto_name, 'Device'), d.device_type,
                       COUNT(a.id), COALESCE(SUM(a.bytes_transferred), 0), COUNT(DISTINCT a.clean_site),
                       COALESCE(SUM(CASE WHEN a.category = 'Academic & Learning' THEN 1 ELSE 0 END), 0),
                       COALESCE(SUM(CASE WHEN a.category = 'Entertainment & Social' THEN 1 ELSE 0 END), 0),
                       COALESCE(SUM(CASE WHEN a.category = 'Gaming & Arcade' THEN 1 ELSE 0 END), 0),
                       COALESCE(SUM(CASE WHEN a.status = 'Blocked' THEN 1 ELSE 0 END), 0)
                FROM devices d LEFT JOIN access_logs a ON a.client_ip = d.ip
                GROUP BY d.ip ORDER BY COUNT(a.id) DESC, d.last_seen DESC
                """
            ).fetchall()
            for ip, dname, dtype, total_r, total_b, uniq_sites, acad_c, ent_c, game_c, blk_c in dev_rows:
                mac = ip_to_mac.get(ip, "")
                stu = mac_to_student.get(mac, {}) if mac else {}
                denom = max(total_r, 1)
                game_ratio = round(game_c / denom, 3)
                threat = "High" if (blk_c > 5 or game_ratio > 0.4) else ("Medium" if (blk_c > 0 or game_ratio > 0.2) else "Low")
                records.append({
                    "client_ip": ip, "client_mac": mac or "UNKNOWN", "device_name": dname,
                    "device_type": dtype or "mobile", "student_prn": stu.get("prn", "UNREGISTERED"),
                    "student_name": stu.get("name", "N/A"), "total_visits": total_r,
                    "total_mb_used": round(total_b / (1024 * 1024), 2),
                    "avg_bytes_per_visit": round(total_b / denom, 1),
                    "unique_domains_visited": uniq_sites,
                    "academic_ratio": round(acad_c / denom, 3),
                    "entertainment_ratio": round(ent_c / denom, 3),
                    "gaming_ratio": game_ratio,
                    "blocked_ratio": round(blk_c / denom, 3),
                    "blocked_count": blk_c,
                    "threat_level": threat,
                })
        elif type == "attendance_ml":
            att_where, att_params = ("WHERE a.session_id = ?", [session_id]) if session_id is not None else ("", [])
            att_rows = c.execute(
                f"""
                SELECT a.id, a.prn, a.student_name, a.batch, a.mac_address, COALESCE(a.ip_address,''),
                       a.attendance_date, a.first_seen, a.last_seen, a.connection_count, COALESCE(a.status, 'Present'),
                       COALESCE(a.department,''), COALESCE(a.year,''), COALESCE(a.division,''),
                       a.session_id, COALESCE(s.session_type,''), COALESCE(s.title,'')
                FROM attendance a LEFT JOIN sessions s ON s.id = a.session_id
                {att_where} ORDER BY a.attendance_date DESC, a.first_seen ASC
                """,
                att_params,
            ).fetchall()
            for r in att_rows:
                aid, prn, name, bat, mac, ip, adate, first_s, last_s, count, status, dept, yr, div, sid, stype, stitle = r
                dur_mins, check_in_hour, is_punctual = 0, 0.0, 1
                try:
                    dt1 = datetime.strptime(first_s, "%Y-%m-%d %H:%M:%S")
                    dt2 = datetime.strptime(last_s, "%Y-%m-%d %H:%M:%S")
                    dur_mins = max(int((dt2 - dt1).total_seconds() / 60), 0)
                    check_in_hour = round(dt1.hour + dt1.minute / 60.0, 2)
                    is_punctual = 1 if (dt1.hour < 9 or (dt1.hour == 9 and dt1.minute <= 30)) else 0
                except Exception:
                    pass
                records.append({
                    "attendance_id": aid, "session_id": sid if sid is not None else "",
                    "session_type": stype or "Legacy", "session_title": stitle, "prn": prn,
                    "student_name": name, "department": dept, "year": yr, "division": div,
                    "batch": bat, "mac_address": mac, "ip_address": ip or "UNKNOWN",
                    "attendance_date": adate, "check_in_time": first_s, "last_active_time": last_s,
                    "check_in_hour": check_in_hour, "duration_minutes": dur_mins,
                    "connection_count": count, "is_punctual": is_punctual, "status": status,
                })

    if format == "json":
        return Response(
            content=json.dumps(records, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename={filename_prefix}.json"},
        )
    output = io.StringIO()
    if records:
        writer = csv.DictWriter(output, fieldnames=list(records[0].keys()), quoting=csv.QUOTE_MINIMAL)
        writer.writeheader()
        writer.writerows(records)
    else:
        output.write("No records found for the specified criteria.")
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename_prefix}.csv"},
    )


# ─── Devices & Logs ───────────────────────────────────────────
@app.get("/api/devices")
def get_devices(mode: str = "clean"):
    with sqlite3.connect(DB_PATH, timeout=15.0) as conn:
        c = conn.cursor()
        device_rows = c.execute(
            "SELECT ip, custom_name, auto_name, device_type, first_seen, last_seen, COALESCE(mac_address, '') FROM devices ORDER BY last_seen DESC"
        ).fetchall()
        bg_filter = "AND is_background = 0" if mode == "clean" else ""
        site_col = "clean_site" if mode == "clean" else "domain"
        devices_list = []

        for ip, custom_name, auto_name, device_type, first_seen, last_seen, dev_mac in device_rows:
            st = c.execute(
                f"SELECT COUNT(*), COALESCE(SUM(bytes_transferred),0), SUM(CASE WHEN status='Blocked' THEN 1 ELSE 0 END), MAX(timestamp) "
                f"FROM access_logs WHERE client_ip=? {bg_filter}",
                (ip,),
            ).fetchone()
            dev_req, dev_bytes, dev_blocked, latest_ts = st[0] or 0, st[1] or 0, st[2] or 0, st[3] or last_seen
            liveness, seconds_ago = calculate_device_liveness(latest_ts)
            if dev_req == 0 and not is_client_ip(ip):
                if not c.execute("SELECT 1 FROM students WHERE mac_address=(SELECT mac_address FROM devices WHERE ip=?)", (ip,)).fetchone():
                    continue
            top_domains = [
                {"domain": r[0], "count": r[1], "bytes": r[2]}
                for r in c.execute(
                    f"SELECT {site_col}, COUNT(*), COALESCE(SUM(bytes_transferred),0) FROM access_logs WHERE client_ip=? {bg_filter} GROUP BY {site_col} ORDER BY COUNT(*) DESC LIMIT 4",
                    (ip,),
                ).fetchall()
            ]
            cat_breakdown = {
                r[0]: r[1]
                for r in c.execute(f"SELECT category, COUNT(*) FROM access_logs WHERE client_ip=? {bg_filter} GROUP BY category", (ip,)).fetchall()
            }
            qrow = c.execute("SELECT daily_mb_limit FROM device_quotas WHERE ip=? AND enabled=1", (ip,)).fetchone()
            quota_mb = qrow[0] if qrow else 0
            used_mb = engine.get_daily_usage_mb(ip) if quota_mb > 0 else 0
            devices_list.append({
                "ip": ip, "mac": dev_mac, "name": custom_name or auto_name,
                "device_type": device_type or "mobile", "first_seen": first_seen, "last_seen": latest_ts,
                "liveness": liveness, "seconds_ago": seconds_ago, "total_requests": dev_req,
                "total_bytes": dev_bytes, "blocked_count": dev_blocked, "top_domains": top_domains,
                "categories": cat_breakdown, "quota_mb": quota_mb, "used_mb": round(used_mb, 2),
            })
    return devices_list


@app.get("/api/devices/{ip}/activity")
def get_device_activity(ip: str, limit: int = 200, mode: str = "clean"):
    with sqlite3.connect(DB_PATH, timeout=15.0) as conn:
        c = conn.cursor()
        bg_filter = "AND is_background=0" if mode == "clean" else ""
        site_col = "clean_site" if mode == "clean" else "domain"
        rows = c.execute(
            f"SELECT id, timestamp, {site_col}, domain, category, method, bytes_transferred, status, risk_flag "
            f"FROM access_logs WHERE client_ip=? {bg_filter} ORDER BY id DESC LIMIT ?",
            (ip, limit),
        ).fetchall()
        summary = c.execute(
            f"SELECT COUNT(*), COALESCE(SUM(bytes_transferred),0), MAX(timestamp) FROM access_logs WHERE client_ip=? {bg_filter}",
            (ip,),
        ).fetchone()
        top_sites = [
            {"domain": r[0], "count": r[1], "bytes": r[2]}
            for r in c.execute(
                f"SELECT {site_col}, COUNT(*), COALESCE(SUM(bytes_transferred),0) FROM access_logs WHERE client_ip=? {bg_filter} GROUP BY {site_col} ORDER BY COUNT(*) DESC LIMIT 10",
                (ip,),
            ).fetchall()
        ]
    return {
        "ip": ip,
        "total_requests": summary[0] or 0,
        "total_bytes": summary[1] or 0,
        "last_seen": summary[2] or "N/A",
        "top_sites": top_sites,
        "logs": [
            {"id": r[0], "timestamp": r[1], "clean_site": r[2], "domain": r[3],
             "category": r[4], "method": r[5], "bytes": r[6], "status": r[7], "risk_flag": r[8]}
            for r in rows
        ],
    }


@app.get("/api/sessions/{ip}")
def get_sessions(ip: str, mode: str = "clean"):
    with sqlite3.connect(DB_PATH, timeout=15.0) as conn:
        bg_filter = "AND is_background=0" if mode == "clean" else ""
        rows = conn.execute(
            f"SELECT timestamp, clean_site, domain, category, bytes_transferred FROM access_logs WHERE client_ip=? {bg_filter} ORDER BY timestamp ASC",
            (ip,),
        ).fetchall()
    logs = [{"timestamp": r[0], "clean_site": r[1], "domain": r[2], "category": r[3], "bytes": r[4] or 0} for r in rows]
    sessions = group_logs_into_sessions(logs)
    return {"ip": ip, "session_count": len(sessions), "sessions": sessions}


@app.put("/api/devices/{ip}/rename")
def rename_device(ip: str, req: RenameRequest):
    name = req.name.strip()
    if not name:
        raise HTTPException(400, "Name cannot be empty")
    engine.rename_device(ip, name)
    return {"status": "ok", "message": f"Renamed to '{name}'"}


@app.delete("/api/devices/{ip}/history")
def clear_device_history(ip: str):
    deleted = engine.clear_device_history(ip)
    return {"status": "ok", "deleted": deleted, "message": f"Cleared {deleted:,} history record(s) for {ip}."}


@app.delete("/api/devices/{ip}")
def remove_device(ip: str):
    found, deleted = engine.remove_device(ip)
    if not found and not deleted:
        raise HTTPException(404, "Device not found.")
    return {"status": "ok", "deleted": deleted, "message": f"Device {ip} removed ({deleted:,} history record(s) deleted)."}


@app.get("/api/logs")
def get_logs(
    limit: int = 100,
    category: Optional[str] = None,
    client_ip: Optional[str] = None,
    search: Optional[str] = None,
    status: Optional[str] = None,
    mode: str = "clean",
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
):
    site_col = "clean_site" if mode == "clean" else "domain"
    query = (
        f"SELECT id,timestamp,client_ip,device_name,device_type,"
        f"{site_col},domain,category,method,bytes_transferred,status,risk_flag,is_background FROM access_logs"
    )
    conds, params = [], []
    if mode == "clean":
        conds.append("is_background=0")
    if category and category != "All":
        conds.append("category=?")
        params.append(category)
    if client_ip and client_ip != "All":
        conds.append("client_ip=?")
        params.append(client_ip)
    if status and status != "All":
        conds.append("status=?")
        params.append(status)
    if search:
        conds.append("(clean_site LIKE ? OR domain LIKE ? OR client_ip LIKE ? OR device_name LIKE ?)")
        p = f"%{search}%"
        params.extend([p, p, p, p])
    if date_from:
        conds.append("timestamp >= ?")
        params.append(f"{date_from} 00:00:00")
    if date_to:
        conds.append("timestamp <= ?")
        params.append(f"{date_to} 23:59:59")
    if conds:
        query += " WHERE " + " AND ".join(conds)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    with sqlite3.connect(DB_PATH, timeout=15.0) as conn:
        rows = conn.execute(query, params).fetchall()
    return [
        {"id": r[0], "timestamp": r[1], "client_ip": r[2], "device_name": r[3],
         "device_type": r[4] or "mobile", "clean_site": r[5], "domain": r[6],
         "category": r[7], "method": r[8], "bytes": r[9], "status": r[10],
         "risk_flag": r[11], "is_background": bool(r[12])}
        for r in rows
    ]


@app.post("/api/logs/clear")
def clear_logs():
    with sqlite3.connect(DB_PATH, timeout=15.0) as conn:
        conn.execute("DELETE FROM access_logs")
        conn.execute("DELETE FROM devices")
    return {"status": "ok", "message": "Logs cleared"}


# ─── Blocklist / Quotas / Latency / Bandwidth ─────────────────
@app.get("/api/policy/rules")
def get_rules():
    with sqlite3.connect(DB_PATH, timeout=15.0) as conn:
        rows = conn.execute("SELECT id,domain,reason,created_at FROM blocklist ORDER BY id DESC").fetchall()
    return [{"id": r[0], "domain": r[1], "reason": r[2], "created_at": r[3]} for r in rows]


@app.post("/api/policy/block")
def block_domain(req: BlockRequest):
    engine.add_block_rule(req.domain, req.reason or "Restricted")
    return {"status": "ok", "message": f"'{req.domain}' blocked (DNS sinkhole active)"}


@app.post("/api/policy/unblock")
def unblock_domain(req: BlockRequest):
    engine.remove_block_rule(req.domain)
    return {"status": "ok", "message": f"'{req.domain}' unblocked"}


@app.get("/api/quota")
def list_quotas():
    with sqlite3.connect(DB_PATH, timeout=15.0) as conn:
        rows = conn.execute("SELECT ip, daily_mb_limit, enabled, created_at FROM device_quotas ORDER BY created_at DESC").fetchall()
    enforced = set(engine.firewall.get_enforced_ips())
    result = []
    for ip, limit_mb, enabled, created_at in rows:
        used = round(engine.get_daily_usage_mb(ip), 2)
        pct = round((used / limit_mb) * 100, 1) if limit_mb > 0 else 0
        result.append({
            "ip": ip, "daily_mb_limit": limit_mb, "enabled": bool(enabled),
            "created_at": created_at, "used_mb": used, "pct": pct,
            "firewall_blocked": ip in enforced,
        })
    return result


@app.get("/api/quota/enforced")
def list_enforced_quotas():
    return {"enforced_ips": engine.firewall.get_enforced_ips(), "dry_run": engine.firewall.dry_run}


@app.post("/api/quota/set")
def set_quota(req: QuotaRequest):
    engine.set_quota(req.ip, req.daily_mb_limit)
    return {"status": "ok", "message": f"Quota set: {req.ip} → {req.daily_mb_limit} MB/day"}


@app.delete("/api/quota/{ip}")
def remove_quota(ip: str):
    engine.remove_quota(ip)
    return {"status": "ok", "message": f"Quota removed for {ip}"}


@app.get("/api/latency")
def get_latency():
    return latency_history


@app.get("/api/latency/targets")
def get_latency_targets():
    with sqlite3.connect(DB_PATH, timeout=15.0) as conn:
        rows = conn.execute("SELECT id, label, host, port, enabled FROM latency_targets ORDER BY id").fetchall()
    return [{"id": r[0], "label": r[1], "host": r[2], "port": r[3], "enabled": bool(r[4])} for r in rows]


@app.post("/api/latency/targets")
def add_latency_target(req: LatencyTargetRequest):
    with sqlite3.connect(DB_PATH, timeout=15.0) as conn:
        conn.execute("INSERT INTO latency_targets (label, host, port, enabled) VALUES (?, ?, ?, 1)", (req.label, req.host, req.port))
    return {"status": "ok", "message": f"Target '{req.label}' added"}


@app.delete("/api/latency/targets/{target_id}")
def remove_latency_target(target_id: int):
    with sqlite3.connect(DB_PATH, timeout=15.0) as conn:
        conn.execute("DELETE FROM latency_targets WHERE id=?", (target_id,))
    return {"status": "ok"}


@app.get("/api/bandwidth/trend")
def bandwidth_trend(mode: str = "clean"):
    since = (datetime.now() - timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")
    bg_f = "AND is_background=0" if mode == "clean" else ""
    with sqlite3.connect(DB_PATH, timeout=15.0) as conn:
        rows = conn.execute(
            f"SELECT strftime('%H:00', timestamp) as hr, COALESCE(SUM(bytes_transferred), 0) "
            f"FROM access_logs WHERE timestamp >= ? {bg_f} GROUP BY hr ORDER BY hr",
            (since,),
        ).fetchall()
    hours = {f"{h:02d}:00": 0 for h in range(24)}
    for hr, b in rows:
        hours[hr] = b
    return [{"hour": k, "bytes": v} for k, v in hours.items()]


@app.get("/api/report")
def generate_report(mode: str = "clean", date_from: Optional[str] = None, date_to: Optional[str] = None):
    bg_f = "AND is_background=0" if mode == "clean" else ""
    date_conds, params_base = "", []
    if date_from:
        date_conds += " AND timestamp >= ?"
        params_base.append(f"{date_from} 00:00:00")
    if date_to:
        date_conds += " AND timestamp <= ?"
        params_base.append(f"{date_to} 23:59:59")

    with sqlite3.connect(DB_PATH, timeout=15.0) as conn:
        c = conn.cursor()
        total_req, total_bytes = c.execute(
            f"SELECT COUNT(*), COALESCE(SUM(bytes_transferred),0) FROM access_logs WHERE 1=1 {bg_f} {date_conds}",
            params_base,
        ).fetchone()
        total_blocked = c.execute("SELECT COUNT(*) FROM access_logs WHERE status='Blocked'").fetchone()[0]
        devices = c.execute(
            f"SELECT client_ip, device_name, COUNT(*), COALESCE(SUM(bytes_transferred),0), MAX(timestamp) "
            f"FROM access_logs WHERE 1=1 {bg_f} {date_conds} GROUP BY client_ip ORDER BY COUNT(*) DESC",
            params_base,
        ).fetchall()

        device_rows_html = ""
        site_col = "clean_site" if mode == "clean" else "domain"
        for ip, name, reqs, byt, last in devices:
            mb = byt / (1024 * 1024)
            device_rows_html += (
                f"<tr><td><strong>{name}</strong><br><small>{ip}</small></td>"
                f"<td>{reqs:,}</td><td>{mb:.2f} MB</td><td>{last[:16] if last else '—'}</td></tr>"
            )

    html = f"""<!doctype html><html><head><meta charset="utf-8"><title>NetPlus Router Audit Report</title>
    <style>body{{font-family:Inter,sans-serif;background:#0b1220;color:#e2e8f0;padding:32px}}
    table{{width:100%;border-collapse:collapse;margin-top:20px}}th,td{{padding:10px;border-bottom:1px solid #1e293b;text-align:left}}</style></head>
    <body><h1>NetPlus Router Gateway — Audit Report</h1>
    <p>Total Requests: <strong>{total_req:,}</strong> | Total Data: <strong>{total_bytes/(1024*1024):.2f} MB</strong> | Blocked: <strong>{total_blocked:,}</strong></p>
    <table><thead><tr><th>Device</th><th>Visits</th><th>Data</th><th>Last Seen</th></tr></thead>
    <tbody>{device_rows_html}</tbody></table></body></html>"""
    return Response(
        content=html,
        media_type="text/html",
        headers={"Content-Disposition": f"attachment; filename=netplus_router_report_{datetime.now().strftime('%Y%m%d')}.html"},
    )


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    loop = asyncio.get_running_loop()
    engine.register_ws(websocket, loop)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        engine.unregister_ws(websocket)
    except Exception:
        engine.unregister_ws(websocket)


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=5000, reload=False)
