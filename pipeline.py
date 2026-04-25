# pipeline.py — AI-Enhanced IP Reputation Pipeline
# Refactored for UI integration: accepts API key + IP list at runtime

import csv
import json
import time
import sqlite3
import logging
import requests
import ipaddress
import math
from datetime import datetime, timezone

# ---------- Config ----------
ABUSE_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
import os
app_dir = os.path.join(os.path.expanduser("~"), ".ip_reputation_pipeline")
os.makedirs(app_dir, exist_ok=True)
CACHE_DB = os.path.join(app_dir, "ip_history.db")
MAX_AGE_DAYS = 90
REQUEST_SLEEP = 1.0

BLOCK_THRESHOLD = 75
REVIEW_THRESHOLD = 40

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


# ---------- Database ----------

def init_db():
    conn = sqlite3.connect(CACHE_DB)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS ip_history (
        ip TEXT PRIMARY KEY,
        first_seen TEXT,
        last_seen TEXT,
        count INTEGER,
        last_abuse_score INTEGER,
        notes TEXT
    )
    """)
    conn.commit()
    return conn


def update_history(conn, ip, abuse_score, note=None):
    cur = conn.cursor()
    t = datetime.now(timezone.utc).isoformat()
    cur.execute("SELECT count FROM ip_history WHERE ip = ?", (ip,))
    row = cur.fetchone()
    if row:
        cur.execute(
            "UPDATE ip_history SET last_seen=?, count=count+1, last_abuse_score=?, notes=? WHERE ip=?",
            (t, abuse_score, note or "", ip)
        )
    else:
        cur.execute(
            "INSERT INTO ip_history(ip, first_seen, last_seen, count, last_abuse_score, notes) VALUES(?,?,?,?,?,?)",
            (ip, t, t, 1, abuse_score, note or "")
        )
    conn.commit()


def get_history(conn, ip):
    cur = conn.cursor()
    cur.execute("SELECT * FROM ip_history WHERE ip = ?", (ip,))
    return cur.fetchone()


# ---------- Validation ----------

def is_public_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return not (
        ip.is_private or ip.is_reserved or
        ip.is_loopback or ip.is_multicast or ip.is_link_local
    )


# ---------- AbuseIPDB Query ----------

def query_abuseipdb(ip, session, api_key, max_age=MAX_AGE_DAYS):
    headers = {"Accept": "application/json", "Key": api_key}
    params = {"ipAddress": ip, "maxAgeInDays": str(max_age)}
    backoff = 1.0

    for attempt in range(6):
        try:
            r = session.get(ABUSE_CHECK_URL, headers=headers, params=params, timeout=15)
        except requests.RequestException as e:
            logging.warning("Network error for %s: %s", ip, e)
            time.sleep(backoff)
            backoff *= 2
            continue

        if r.status_code == 200:
            return r.json().get("data", {})

        elif r.status_code == 429:
            ra = r.headers.get("Retry-After")
            wait = float(ra) if ra else backoff
            logging.warning("429 for %s, waiting %s seconds", ip, wait)
            time.sleep(wait)
            backoff *= 2

        elif 500 <= r.status_code < 600:
            logging.warning("Server error %s for %s", r.status_code, ip)
            time.sleep(backoff)
            backoff *= 2

        else:
            logging.error("Unexpected status %s for %s: %s", r.status_code, ip, r.text[:200])
            return None

    logging.error("Exceeded retries for %s", ip)
    return None


# ---------- Rule Engine (Stage 1) ----------

def compute_score_and_decision(abuse_data, local_history):
    reasons = []

    if not abuse_data:
        reasons.append("No enrichment data available")
        return 20, "REVIEW", reasons

    acs = abuse_data.get("abuseConfidenceScore") or 0
    tr = abuse_data.get("totalReports") or 0
    usage = abuse_data.get("usageType")
    is_whitelisted = abuse_data.get("isWhitelisted")

    score = int(acs)

    if tr > 0:
        score += int(min(10, math.log(tr + 1) * 2))

    if is_whitelisted:
        score = max(0, score - 20)
        reasons.append("IP is whitelisted (known trusted source)")

    if usage and "Data Center" in usage:
        reasons.append(f"Usage type: {usage}")

    if local_history:
        last_count = local_history[3]
        if last_count >= 3:
            score += 10
            reasons.append(f"Seen {last_count} times in local history")

    if score >= BLOCK_THRESHOLD:
        decision = "BLOCK"
        reasons.append(f"Abuse score {score} meets block threshold ({BLOCK_THRESHOLD})")
    elif score >= REVIEW_THRESHOLD:
        decision = "REVIEW"
        reasons.append(f"Abuse score {score} meets review threshold ({REVIEW_THRESHOLD})")
    else:
        decision = "ALLOW"
        reasons.append(f"Abuse score {score} below review threshold ({REVIEW_THRESHOLD})")

    return score, decision, reasons


# ---------- AI Heuristic Layer (Stage 2) ----------

def ai_adjust_decision(score, decision, abuse_data, history, reasons):
    ip_seen_count = history[3] if history else 0
    usage = abuse_data.get("usageType") if abuse_data else None
    reports = abuse_data.get("totalReports") if abuse_data else 0

    # Rule 1: Data center with repeated reports → raise to REVIEW
    if usage and "Data Center" in usage and reports >= 5:
        if decision == "ALLOW":
            decision = "REVIEW"
            score += 10
            reasons.append("AI: Data center with repeated reports — raised to REVIEW")

    # Rule 2: Frequent internal history → raise attention
    if ip_seen_count >= 5 and decision != "BLOCK":
        decision = "REVIEW"
        score = max(score, 50)
        reasons.append("AI: Frequent historical activity detected — flagged for review")

    # Rule 3: Clean IP with no reports → soften to ALLOW
    if reports == 0 and ip_seen_count <= 1 and score < REVIEW_THRESHOLD:
        decision = "ALLOW"
        reasons.append("AI: No reports and clean history — softened to ALLOW")

    # Rule 4: Extremely high score → enforce BLOCK
    if score >= 90:
        decision = "BLOCK"
        reasons.append("AI: Extremely high abuse score — enforcing BLOCK")

    return score, decision, reasons


# ---------- Main Pipeline ----------
#
# CHANGES FROM ORIGINAL:
#   - Removed: input file path argument, os.getenv() API key
#   - Added:   ip_list (Python list), api_key (runtime param),
#              progress_callback(current, total) for UI progress bar,
#              output_path (user-chosen save location)
#   - Returns: list of result dicts so the UI can populate a table
#              without re-reading the CSV file

def process_ip_list(ip_list, api_key, progress_callback=None, output_path=None):
    """
    Process a list of IP strings and write results to output_path (CSV).

    Parameters
    ----------
    ip_list           : list[str]  — IP addresses from the UI paste box
    api_key           : str        — AbuseIPDB key entered at runtime; never written to disk
    progress_callback : callable   — optional fn(current, total) to drive a progress bar
    output_path       : str        — full file path for CSV output (from save dialog)

    Returns
    -------
    list[dict] — one dict per IP, matching the CSV columns, for live UI display
    """
    if not api_key or not api_key.strip():
        raise ValueError("API key is required.")

    if not output_path:
        output_path = "ip_decisions.csv"

    conn = init_db()
    session = requests.Session()
    results = []

    # Deduplicate while preserving input order
    seen_ips = set()
    unique_ips = []
    for ip in ip_list:
        ip = ip.strip()
        if ip and ip not in seen_ips:
            seen_ips.add(ip)
            unique_ips.append(ip)

    total = len(unique_ips)

    with open(output_path, "w", newline="") as outf:
        writer = csv.DictWriter(outf, fieldnames=[
            "ip", "decision", "score", "reasons",
            "abuse_data", "history", "timestamp"
        ])
        writer.writeheader()

        for idx, ip_raw in enumerate(unique_ips):

            # Update UI progress bar
            if progress_callback:
                progress_callback(idx + 1, total)

            # Skip invalid / private / reserved addresses
            if not is_public_ip(ip_raw):
                row = {
                    "ip": ip_raw,
                    "decision": "SKIP",
                    "score": 0,
                    "reasons": "Invalid, private, or reserved address",
                    "abuse_data": "{}",
                    "history": "{}",
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
                writer.writerow(row)
                results.append(row)
                continue

            # Cache check — skip API if seen within last 24 hours
            hist = get_history(conn, ip_raw)
            use_cache = False

            if hist:
                last_dt = datetime.fromisoformat(hist[2])
                if (datetime.now(timezone.utc) - last_dt).total_seconds() < 86400:
                    use_cache = True
                    abuse_data = {
                        "abuseConfidenceScore": hist[4],
                        "totalReports": 0
                    }
                    logging.info("Cache hit for %s", ip_raw)

            # Live API query
            if not use_cache:
                abuse_data = query_abuseipdb(ip_raw, session, api_key)
                time.sleep(REQUEST_SLEEP)

            # Stage 1 — rule engine
            score, decision, reasons = compute_score_and_decision(abuse_data, hist)

            # Stage 2 — AI heuristics
            score, decision, reasons = ai_adjust_decision(
                score, decision, abuse_data, hist, reasons
            )

            # Persist result to local DB
            update_history(conn, ip_raw, score, note="auto-scored")
            hist_after = get_history(conn, ip_raw)

            row = {
                "ip": ip_raw,
                "decision": decision,
                "score": score,
                "reasons": "; ".join(reasons),
                "abuse_data": json.dumps(abuse_data or {}),
                "history": json.dumps(hist_after or {}),
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            writer.writerow(row)
            results.append(row)

            logging.info("Processed %s -> %s (score: %s)", ip_raw, decision, score)

    conn.close()
    logging.info("Done. Output written to %s", output_path)
    return results
