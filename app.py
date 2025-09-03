#!/usr/bin/env python3
"""
More Retail – Streamlit Orchestrator
Tabs:
  1) Gmail → Drive (gmailtodrive.py)
  2) Drive → Sheet (pdftoexcel.py)
  3) Combined (runs 1, then 2 sequentially)
  4) Logs (live run log)

Auth:
  - Uses the same web-based OAuth logic style as app(2).py, driven by Streamlit secrets.

Notes:
  - All base configs are hardcoded and shown after authentication.
  - Runtime-adjustable params: (days_back, max_results) for Gmail→Drive; (days_back) for Drive→Sheet.
  - Each workflow has a Start button; execution stops at completion (no auto-restarts).
  - End-of-run stats include: processed/failed files, rows appended, duplicate rows in sheet.
"""

import os
import json
import time
import queue
import threading
from typing import Dict, Any, List

import streamlit as st
from datetime import datetime, timedelta

# Google API libs
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build

# Local workflow modules
from gmailtodrive import GmailGDriveAutomation
from pdftoexcel import DrivePDFProcessor

# =====================
# Page & Session Setup
# =====================
st.set_page_config(page_title="More Retail – AWS (Gmail→Drive→Sheet)", page_icon="📦", layout="wide")

if "log_queue" not in st.session_state:
    st.session_state.log_queue = queue.Queue()
if "logs" not in st.session_state:
    st.session_state.logs = []  # list of {ts, level, text}
if "running" not in st.session_state:
    st.session_state.running = False
if "result_stats" not in st.session_state:
    st.session_state.result_stats = {}

# =====================
# Hardcoded base config
# =====================
DEFAULT_GMAIL_CONFIG = {
    "sender": "aws-reports@moreretail.in",
    "search_term": "in:span ",
    "gdrive_folder_id": "1gZoNjdGarwMD5-Ci3uoqjNZZ8bTNyVoy",  # destination base folder
    # runtime params (UI-controlled): days_back, max_results
}

DEFAULT_PDF_CONFIG = {
    "drive_folder_id": "1XHIFX-Gsb_Mx_AYjoi2NG1vMlvNE5CmQ",  # source PDFs folder
    "spreadsheet_id": "16y9DAK2tVHgnZNnPeRoSSPPE2NcspW_qqMF8ZR8OOC0",
    "sheet_range": "mraws",  # e.g., "Sheet1" or "Sheet1!A:Z"
    "llama_agent": "More retail Agent",  # shown for transparency; key is taken from secrets
    # runtime param (UI-controlled): days_back
}

# =====================
# Helpers: Logging
# =====================
LEVEL_EMOJI = {"info": "ℹ️", "success": "✅", "warning": "⚠️", "error": "❌", "status": "⏳"}

def push_log(level: str, text: str):
    st.session_state.log_queue.put({"level": level, "text": text, "ts": datetime.now().strftime("%H:%M:%S")})

# =====================
# OAuth (adapted style of app(2).py)
# =====================
class Auth:
    def __init__(self):
        self.gmail_scopes = ['https://www.googleapis.com/auth/gmail.readonly']
        self.drive_scopes = ['https://www.googleapis.com/auth/drive.file']
        self.sheets_scopes = ['https://www.googleapis.com/auth/spreadsheets']
        self.gmail_service = None
        self.drive_service = None
        self.sheets_service = None

    def authenticate_from_secrets(self) -> bool:
        """Authenticate using web-based OAuth, storing token in session_state (pattern from app(2).py).
        Expects secrets like:
        [google]
        client_id = "..."
        client_secret = "..."
        redirect_uri = "https://moreretailaws.streamlit.app/"  # or your deployed app URL
        llama_api_key = "llx-..."  # optional for PDF step
        """
        try:
            push_log("status", "Authenticating with Google APIs")
            combined_scopes = list(set(self.gmail_scopes + self.drive_scopes + self.sheets_scopes))

            # Reuse token if present
            if 'oauth_token' in st.session_state:
                creds = Credentials.from_authorized_user_info(st.session_state['oauth_token'], combined_scopes)
                if creds and creds.valid:
                    self._build_services(creds)
                    push_log("success", "Authentication already active")
                    return True
                if creds and creds.expired and creds.refresh_token:
                    creds.refresh(Request())
                    self._store_token(creds)
                    self._build_services(creds)
                    push_log("success", "Authentication refreshed")
                    return True

            # Fresh auth using client secrets from Streamlit secrets
          gsec = st.secrets.get("google", {})
          creds_json = gsec.get("credentials_json")
          if not creds_json:
              push_log("error", "Missing 'credentials_json' in Streamlit secrets")
              return False
          
          client_config = json.loads(creds_json)
          flow = Flow.from_client_config(client_config, scopes=combined_scopes)
          
          # Pick redirect URI dynamically
          redirect_uris = client_config["web"].get("redirect_uris", [])
          if redirect_uris:
              # Prefer cloud deployment redirect if IS_CLOUD_DEPLOYMENT is true
              if gsec.get("IS_CLOUD_DEPLOYMENT", False):
                  redirect_uri = [u for u in redirect_uris if "streamlit.app" in u][0]
              else:
                  redirect_uri = redirect_uris[0]
            flow.redirect_uri = redirect_uri


            # If a code is present in query params, fetch token
            code = st.query_params.get("code")
            if code:
                flow.fetch_token(code=code)
                creds = flow.credentials
                self._store_token(creds)
                self._build_services(creds)
                # clear code param
                st.query_params.clear()
                push_log("success", "Authentication successful")
                return True

            # else show a login link and stop
            auth_url, _ = flow.authorization_url(prompt='consent', access_type='offline', include_granted_scopes='true')
            st.markdown("### Google Authentication Required")
            st.markdown(f"[Authorize with Google]({auth_url})")
            st.info("Click the link above to authorize. You'll be redirected back here automatically.")
            st.stop()
        except Exception as e:
            push_log("error", f"Authentication failed: {e}")
            return False

    def _store_token(self, creds: Credentials):
        st.session_state['oauth_token'] = json.loads(creds.to_json())

    def _build_services(self, creds: Credentials):
        self.gmail_service = build('gmail', 'v1', credentials=creds)
        self.drive_service = build('drive', 'v3', credentials=creds)
        self.sheets_service = build('sheets', 'v4', credentials=creds)

# =====================
# Stats helpers
# =====================

def compute_sheet_duplicates(sheets_service, spreadsheet_id: str, sheet_range: str) -> Dict[str, int]:
    """Compute duplicate row count in a sheet (exact row duplicates, excluding header)."""
    try:
        result = sheets_service.spreadsheets().values().get(
            spreadsheetId=spreadsheet_id,
            range=sheet_range.split('!')[0],
            majorDimension="ROWS",
        ).execute()
        rows = result.get('values', [])
        if not rows:
            return {"total_rows": 0, "duplicate_rows": 0}
        data = rows[1:] if len(rows) > 1 else []  # exclude header
        seen = set()
        dupes = 0
        for r in data:
            key = tuple(r)
            if key in seen:
                dupes += 1
            else:
                seen.add(key)
        return {"total_rows": len(data), "duplicate_rows": dupes}
    except Exception:
        return {"total_rows": 0, "duplicate_rows": 0}

# =====================
# Workers
# =====================

def run_gmail_to_drive(auth: Auth, base_cfg: Dict[str, Any], days_back: int, max_results: int) -> Dict[str, Any]:
    push_log("status", "Starting Gmail → Drive workflow")
    # Instantiate module class and inject services
    gd = GmailGDriveAutomation(credentials_path="unused.json", gdrive_folder_id=base_cfg["gdrive_folder_id"])  # path unused
    gd.gmail_service = auth.gmail_service
    gd.drive_service = auth.drive_service

    # Build search, run
    emails = []
    try:
        # Reuse search method if available in module
        emails = gd.search_emails(base_cfg.get("sender", ""), base_cfg.get("search_term", ""), days_back, max_results)
        push_log("info", f"Gmail search returned {len(emails)} messages")
    except Exception as e:
        push_log("error", f"Search failed: {e}")
        return {"ok": False, "processed_files": 0, "failed_files": 0}

    try:
        stats = gd.process_emails(emails, base_cfg.get("search_term", ""))
        # Normalize for UI
        processed = stats.get("successful_uploads", 0)
        failed = stats.get("failed_uploads", 0)
        push_log("success", f"Gmail → Drive completed | uploads: {processed}, failed: {failed}")
        return {"ok": True, "processed_files": processed, "failed_files": failed}
    except Exception as e:
        push_log("error", f"Processing failed: {e}")
        return {"ok": False, "processed_files": 0, "failed_files": len(emails)}


def run_drive_to_sheet(auth: Auth, base_cfg: Dict[str, Any], days_back: int) -> Dict[str, Any]:
    push_log("status", "Starting Drive → Sheet workflow")
    # Instantiate module class and inject services
    px = DrivePDFProcessor(credentials_path="unused.json")  # path unused
    px.drive_service = auth.drive_service
    px.sheets_service = auth.sheets_service

    # Prepare llama key from secrets (never hardcode)
    llama_key = st.secrets.get("google", {}).get("llama_api_key", "")
    if llama_key:
        os.environ["LLAMA_CLOUD_API_KEY"] = llama_key

    # Call the module's higher-level method to do everything
    try:
        stats = px.process_pdfs(
            drive_folder_id=base_cfg["drive_folder_id"],
            api_key=llama_key,
            agent_name=base_cfg["llama_agent"],
            spreadsheet_id=base_cfg["spreadsheet_id"],
            sheet_range=base_cfg["sheet_range"],
            days_back=days_back,
        )
        rows_added = stats.get("rows_added", 0)
        processed_pdfs = stats.get("processed_pdfs", 0)
        failed_pdfs = stats.get("failed_pdfs", 0)

        # Compute duplicates in sheet after append
        dup_info = compute_sheet_duplicates(auth.sheets_service, base_cfg["spreadsheet_id"], base_cfg["sheet_range"])
        push_log("success", f"Drive → Sheet completed | PDFs: {processed_pdfs} ok / {failed_pdfs} fail | rows added: {rows_added} | duplicates now: {dup_info['duplicate_rows']}")
        return {
            "ok": True,
            "processed_files": processed_pdfs,
            "failed_files": failed_pdfs,
            "rows_appended": rows_added,
            "duplicate_rows": dup_info["duplicate_rows"],
        }
    except Exception as e:
        push_log("error", f"Drive → Sheet failed: {e}")
        return {"ok": False, "processed_files": 0, "failed_files": 0, "rows_appended": 0, "duplicate_rows": 0}


# Thread target

def workflow_thread(kind: str, auth: Auth, gmail_cfg: Dict[str, Any], pdf_cfg: Dict[str, Any], gmail_days: int, gmail_max: int, pdf_days: int):
    try:
        if kind == "gmail":
            res_g = run_gmail_to_drive(auth, gmail_cfg, gmail_days, gmail_max)
            st.session_state.result_stats = {"gmail": res_g}
        elif kind == "pdf":
            res_p = run_drive_to_sheet(auth, pdf_cfg, pdf_days)
            st.session_state.result_stats = {"pdf": res_p}
        elif kind == "combined":
            res_g = run_gmail_to_drive(auth, gmail_cfg, gmail_days, gmail_max)
            res_p = run_drive_to_sheet(auth, pdf_cfg, pdf_days)
            st.session_state.result_stats = {"gmail": res_g, "pdf": res_p}
        push_log("status", "Workflow finished")
    finally:
        st.session_state.running = False

# =====================
# UI
# =====================

st.title("More Retail – AWS Attachment Processing")

# Auth gate
auth = Auth()
if not auth.authenticate_from_secrets():
    st.stop()

# Show configs after auth
with st.expander("🔧 Hardcoded Config (read-only)", expanded=True):
    c1, c2 = st.columns(2)
    with c1:
        st.subheader("Gmail → Drive Config")
        st.json(DEFAULT_GMAIL_CONFIG)
    with c2:
        st.subheader("Drive → Sheet Config")
        # mask llama key only (key itself is stored in secrets)
        masked = DEFAULT_PDF_CONFIG.copy()
        st.json(masked)

# Runtime parameter controls are inside tabs

TAB_G2D, TAB_D2S, TAB_COMBINED, TAB_LOGS = st.tabs([
    "Gmail → Drive", "Drive → Sheet", "Combined", "Logs"
])

# --- Gmail → Drive tab ---
with TAB_G2D:
    st.subheader("Gmail → Drive (aws-reports)")
    colA, colB, colC = st.columns(3)
    with colA:
        g_days = st.number_input("Days back", min_value=1, value=7)
    with colB:
        g_max = st.number_input("Max results", min_value=1, value=200)
    with colC:
        st.write("")
        st.write("")
        start_g = st.button("Start Gmail → Drive", use_container_width=True, disabled=st.session_state.running)
    if start_g and not st.session_state.running:
        st.session_state.running = True
        push_log("info", f"Queued Gmail→Drive (days_back={g_days}, max_results={g_max})")
        threading.Thread(target=workflow_thread, args=("gmail", auth, DEFAULT_GMAIL_CONFIG, DEFAULT_PDF_CONFIG, g_days, g_max, 1), daemon=True).start()

    # Show last result summary for this tab
    if st.session_state.result_stats.get("gmail"):
        r = st.session_state.result_stats["gmail"]
        st.success(f"Completed | uploads: {r.get('processed_files',0)} | failed: {r.get('failed_files',0)}")

# --- Drive → Sheet tab ---
with TAB_D2S:
    st.subheader("Drive → Sheet (LlamaParse)")
    colA, colB = st.columns(2)
    with colA:
        p_days = st.number_input("Days back (PDFs)", min_value=1, value=1)
    with colB:
        st.write("")
        st.write("")
        start_p = st.button("Start Drive → Sheet", use_container_width=True, disabled=st.session_state.running)
    if start_p and not st.session_state.running:
        st.session_state.running = True
        push_log("info", f"Queued Drive→Sheet (days_back={p_days})")
        threading.Thread(target=workflow_thread, args=("pdf", auth, DEFAULT_GMAIL_CONFIG, DEFAULT_PDF_CONFIG, 7, 100, p_days), daemon=True).start()

    if st.session_state.result_stats.get("pdf"):
        r = st.session_state.result_stats["pdf"]
        st.success(
            f"Completed | PDFs ok: {r.get('processed_files',0)} | failed: {r.get('failed_files',0)} | rows appended: {r.get('rows_appended',0)} | duplicate rows: {r.get('duplicate_rows',0)}"
        )

# --- Combined tab ---
with TAB_COMBINED:
    st.subheader("Combined: Gmail → Drive, then Drive → Sheet")
    colA, colB, colC = st.columns(3)
    with colA:
        g_days_c = st.number_input("Gmail days back", key="g_days_c", min_value=1, value=7)
    with colB:
        g_max_c = st.number_input("Gmail max results", key="g_max_c", min_value=1, value=200)
    with colC:
        p_days_c = st.number_input("PDF days back", key="p_days_c", min_value=1, value=1)
    start_c = st.button("Start Combined", use_container_width=True, disabled=st.session_state.running)
    if start_c and not st.session_state.running:
        st.session_state.running = True
        push_log("info", f"Queued Combined (g_days={g_days_c}, g_max={g_max_c}, p_days={p_days_c})")
        threading.Thread(target=workflow_thread, args=("combined", auth, DEFAULT_GMAIL_CONFIG, DEFAULT_PDF_CONFIG, g_days_c, g_max_c, p_days_c), daemon=True).start()

    if st.session_state.result_stats.get("gmail") or st.session_state.result_stats.get("pdf"):
        g = st.session_state.result_stats.get("gmail", {})
        p = st.session_state.result_stats.get("pdf", {})
        st.success(
            f"Gmail → Drive: uploads {g.get('processed_files',0)} / failed {g.get('failed_files',0)}  |  "
            f"Drive → Sheet: PDFs {p.get('processed_files',0)} ok / {p.get('failed_files',0)} fail, rows {p.get('rows_appended',0)}, dupes {p.get('duplicate_rows',0)}"
        )

# --- Logs tab ---
with TAB_LOGS:
    st.subheader("Run Log")

    # Drain queue to logs list
    while not st.session_state.log_queue.empty():
        st.session_state.logs.append(st.session_state.log_queue.get())

    # Only keep last ~500 lines
    st.session_state.logs = st.session_state.logs[-500:]

    # Render
    for item in st.session_state.logs:
        emoji = LEVEL_EMOJI.get(item.get("level"), "•")
        st.write(f"{item['ts']} {emoji} {item['text']}")

    # Live refresh area (simple auto refresh by re-running script when running)
    if st.session_state.running:
        st.caption("Workflow running – logs will update live. (This app does not auto-restart workflows.)")
        st.experimental_rerun()
