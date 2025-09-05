#!/usr/bin/env python3
"""
Streamlit App for More Retail Docs
Combines Gmail to Drive and PDF to Sheet Workflows with real-time tracking
"""

import streamlit as st
import os
import json
import base64
import tempfile
import time
import logging
import pandas as pd
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional
from io import StringIO, BytesIO
import threading
import queue
import re
import warnings

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow, Flow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from googleapiclient.http import MediaIoBaseUpload, MediaIoBaseDownload

# Add LlamaParse import
try:
    from llama_cloud_services import LlamaExtract
    LLAMA_AVAILABLE = True
except ImportError:
    LLAMA_AVAILABLE = False

warnings.filterwarnings("ignore")

# Configure Streamlit page
st.set_page_config(
    page_title="More Retail Docs Automation",
    page_icon="🤖",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Hardcoded configuration based on scripts
CONFIG = {
    'gmail': {
        'sender': 'docs@more.in',
        'search_term': 'grn',
        'gdrive_folder_id': '1gZoNjdGarwMD5-Ci3uoqjNZZ8bTNyVoy'
    },
    'pdf': {
        'llama_api_key': 'llx-DkwQuIwq5RVZk247W0r5WCdywejPI5CybuTDJgAUUcZKNq0A',
        'llama_agent': 'More retail Agent',
        'drive_folder_id': '1C251csI1oOeX_skv7mfqpZB0NbyLLd9d',
        'spreadsheet_id': '16y9DAK2tVHgnZNnPeRoSSPPE2NcspW_qqMF8ZR8OOC0',
        'sheet_range': 'mrgrn'
    }
}

class GmailGDriveAutomation:
    def __init__(self, gmail_service, drive_service, gdrive_folder_id: Optional[str] = None):
        self.gmail_service = gmail_service
        self.drive_service = drive_service
        self.gdrive_folder_id = gdrive_folder_id
    
    def sanitize_filename(self, filename: str) -> str:
        cleaned = re.sub(r'[<>:"/\\|?*]', '_', filename)
        if len(cleaned) > 100:
            name_parts = cleaned.split('.')
            if len(name_parts) > 1:
                extension = name_parts[-1]
                base_name = '.'.join(name_parts[:-1])
                cleaned = f"{base_name[:95]}.{extension}"
            else:
                cleaned = cleaned[:100]
        return cleaned
    
    def classify_extension(self, filename: str) -> str:
        if not filename or '.' not in filename:
            return "Other"
            
        ext = filename.split(".")[-1].lower()
        
        type_map = {
            "pdf": "PDFs",
            "doc": "Documents", "docx": "Documents", "txt": "Documents",
            "xls": "Spreadsheets", "xlsx": "Spreadsheets", "csv": "Spreadsheets",
            "jpg": "Images", "jpeg": "Images", "png": "Images", "gif": "Images",
            "ppt": "Presentations", "pptx": "Presentations",
            "zip": "Archives", "rar": "Archives", "7z": "Archives",
        }
        
        return type_map.get(ext, "Other")
    
    def search_emails(self, sender: str = "", search_term: str = "", 
                      days_back: int = 7, max_results: int = 50) -> List[Dict]:
        try:
            query_parts = ["has:attachment"]
            
            if sender:
                query_parts.append(f"from:{sender}")
            
            if search_term:
                if "," in search_term:
                    keywords = [k.strip() for k in search_term.split(",")]
                    keyword_query = " OR ".join([f'"{k}"' for k in keywords if k])
                    if keyword_query:
                        query_parts.append(f"({keyword_query})")
                else:
                    query_parts.append(f'"{search_term}"')
            
            start_date = datetime.now() - timedelta(days=days_back)
            query_parts.append(f"after:{start_date.strftime('%Y/%m/%d')}")
            
            query = " ".join(query_parts)
            st.session_state.automation.log(f"Searching Gmail with query: {query}")
            
            result = self.gmail_service.users().messages().list(
                userId='me', q=query, maxResults=max_results
            ).execute()
            
            messages = result.get('messages', [])
            st.session_state.automation.log(f"Found {len(messages)} emails matching criteria")
            
            return messages
            
        except Exception as e:
            st.session_state.automation.log(f"Email search failed: {str(e)}", "ERROR")
            return []
    
    def get_email_details(self, message_id: str) -> Dict:
        try:
            message = self.gmail_service.users().messages().get(
                userId='me', id=message_id, format='metadata'
            ).execute()
            
            headers = message['payload'].get('headers', [])
            
            details = {
                'id': message_id,
                'sender': next((h['value'] for h in headers if h['name'] == "From"), "Unknown"),
                'subject': next((h['value'] for h in headers if h['name'] == "Subject"), "(No Subject)"),
                'date': next((h['value'] for h in headers if h['name'] == "Date"), "")
            }
            
            return details
            
        except Exception as e:
            st.session_state.automation.log(f"Failed to get email details for {message_id}: {str(e)}", "ERROR")
            return {}
    
    def create_drive_folder(self, folder_name: str, parent_folder_id: Optional[str] = None) -> str:
        try:
            query = f"name='{folder_name}' and mimeType='application/vnd.google-apps.folder' and trashed=false"
            if parent_folder_id:
                query += f" and '{parent_folder_id}' in parents"
            
            existing = self.drive_service.files().list(q=query, fields='files(id, name)').execute()
            files = existing.get('files', [])
            
            if files:
                folder_id = files[0]['id']
                st.session_state.automation.log(f"Using existing folder: {folder_name} (ID: {folder_id})")
                return folder_id
            
            folder_metadata = {
                'name': folder_name,
                'mimeType': 'application/vnd.google-apps.folder'
            }
            
            if parent_folder_id:
                folder_metadata['parents'] = [parent_folder_id]
            
            folder = self.drive_service.files().create(
                body=folder_metadata,
                fields='id'
            ).execute()
            
            folder_id = folder.get('id')
            st.session_state.automation.log(f"Created Google Drive folder: {folder_name} (ID: {folder_id})")
            
            return folder_id
            
        except Exception as e:
            st.session_state.automation.log(f"Failed to create folder {folder_name}: {str(e)}", "ERROR")
            return ""
    
    def upload_to_drive(self, file_data: bytes, filename: str, folder_id: str) -> bool:
        try:
            query = f"name='{filename}' and '{folder_id}' in parents and trashed=false"
            existing = self.drive_service.files().list(q=query, fields='files(id, name)').execute()
            files = existing.get('files', [])
            
            if files:
                st.session_state.automation.log(f"File already exists, skipping: {filename}")
                return True
            
            file_metadata = {
                'name': filename,
                'parents': [folder_id] if folder_id else []
            }
            
            media = MediaIoBaseUpload(
                io.BytesIO(file_data),
                mimetype='application/octet-stream',
                resumable=True
            )
            
            file = self.drive_service.files().create(
                body=file_metadata,
                media_body=media,
                fields='id'
            ).execute()
            
            st.session_state.automation.log(f"Uploaded to Drive: {filename}")
            return True
            
        except Exception as e:
            st.session_state.automation.log(f"Failed to upload {filename}: {str(e)}", "ERROR")
            return False
    
    def process_attachment(self, message_id: str, part: Dict, sender_info: Dict, 
                           search_term: str, base_folder_id: str) -> bool:
        try:
            filename = part.get("filename", "")
            if not filename:
                return False
            
            final_filename = self.sanitize_filename(filename)

            attachment_id = part["body"].get("attachmentId")
            if not attachment_id:
                return False
            
            att = self.gmail_service.users().messages().attachments().get(
                userId='me', messageId=message_id, id=attachment_id
            ).execute()
            
            if not att.get("data"):
                return False
            
            file_data = base64.urlsafe_b64decode(att["data"].encode("UTF-8"))
            
            sender_email = sender_info.get('sender', 'Unknown')
            if "<" in sender_email and ">" in sender_email:
                sender_email = sender_email.split("<")[1].split(">")[0].strip()
            
            sender_folder_name = self.sanitize_filename(sender_email)
            search_folder_name = search_term if search_term else "all-attachments"
            file_type_folder = self.classify_extension(filename)
            
            sender_folder_id = self.create_drive_folder(sender_folder_name, base_folder_id)
            search_folder_id = self.create_drive_folder(search_folder_name, sender_folder_id)
            type_folder_id = self.create_drive_folder(file_type_folder, search_folder_id)
            
            success = self.upload_to_drive(file_data, final_filename, type_folder_id)
            
            if success:
                st.session_state.automation.log(f"Processed attachment: {filename}")
            
            return success
            
        except Exception as e:
            st.session_state.automation.log(f"Failed to process attachment {part.get('filename', 'unknown')}: {str(e)}", "ERROR")
            return False
    
    def extract_attachments_from_email(self, message_id: str, payload: Dict, 
                                       sender_info: Dict, search_term: str, 
                                       base_folder_id: str) -> int:
        processed_count = 0
        
        if "parts" in payload:
            for part in payload["parts"]:
                processed_count += self.extract_attachments_from_email(
                    message_id, part, sender_info, search_term, base_folder_id
                )
        
        elif payload.get("filename") and "attachmentId" in payload.get("body", {}):
            if self.process_attachment(message_id, payload, sender_info, search_term, base_folder_id):
                processed_count += 1
        
        return processed_count
    
    def process_emails(self, emails: List[Dict], search_term: str = "") -> Dict:
        stats = {
            'total_emails': len(emails),
            'processed_emails': 0,
            'total_attachments': 0,
            'successful_uploads': 0,
            'failed_uploads': 0
        }
        
        if not emails:
            st.session_state.automation.log("No emails to process")
            return stats
        
        base_folder_name = f"Gmail_Attachments"
        base_folder_id = self.create_drive_folder(base_folder_name, self.gdrive_folder_id)
        if not base_folder_id:
            st.session_state.automation.log("Failed to create base folder in Google Drive", "ERROR")
            return stats
        
        st.session_state.automation.log(f"Processing {len(emails)} emails...")
        
        for i, email in enumerate(emails, 1):
            try:
                sender_info = self.get_email_details(email['id'])
                if not sender_info:
                    continue
                
                message = self.gmail_service.users().messages().get(
                    userId='me', id=email['id']
                ).execute()
                
                if not message or not message.get('payload'):
                    continue
                
                attachment_count = self.extract_attachments_from_email(
                    email['id'], message['payload'], sender_info, search_term, base_folder_id
                )
                
                stats['total_attachments'] += attachment_count
                stats['successful_uploads'] += attachment_count
                stats['processed_emails'] += 1
                
                subject = sender_info.get('subject', 'No Subject')[:50]
                st.session_state.automation.log(f"Found {attachment_count} attachments in email: {subject}")
                
            except Exception as e:
                st.session_state.automation.log(f"Failed to process email {email.get('id', 'unknown')}: {str(e)}", "ERROR")
                stats['failed_uploads'] += 1
        
        return stats

class DrivePDFProcessor:
    def __init__(self, drive_service, sheets_service):
        self.drive_service = drive_service
        self.sheets_service = sheets_service
    
    def list_drive_files(self, folder_id: str, days_back: int = None) -> List[Dict]:
        try:
            query = f"'{folder_id}' in parents and mimeType='application/pdf' and trashed=false"
            
            if days_back is not None:
                today_utc = datetime.now(timezone.utc)
                start_date = today_utc - timedelta(days=days_back - 1)
                start_date = start_date.replace(hour=0, minute=0, second=0, microsecond=0)
                start_str = start_date.strftime('%Y-%m-%dT%H:%M:%SZ')
                query += f" and createdTime >= '{start_str}'"
                st.session_state.automation.log(f"Applying date filter: createdTime >= {start_str}")
            
            files = []
            page_token = None

            while True:
                results = self.drive_service.files().list(
                    q=query,
                    fields="nextPageToken, files(id, name, mimeType, createdTime, modifiedTime)",
                    orderBy="createdTime desc",
                    pageToken=page_token,
                    pageSize=100
                ).execute()
                
                files.extend(results.get('files', []))
                page_token = results.get('nextPageToken', None)
                
                if page_token is None:
                    break

            st.session_state.automation.log(f"Found {len(files)} PDF files in folder {folder_id}")
            
            return files

        except Exception as e:
            st.session_state.automation.log(f"Failed to list files in folder {folder_id}: {str(e)}", "ERROR")
            return []
    
    def download_from_drive(self, file_id: str, file_name: str) -> bytes:
        try:
            request = self.drive_service.files().get_media(fileId=file_id)
            file_data = request.execute()
            return file_data
        except Exception as e:
            st.session_state.automation.log(f"Failed to download file {file_name}: {str(e)}", "ERROR")
            return b""
    
    def append_to_google_sheet(self, spreadsheet_id: str, range_name: str, values: List[List[Any]]):
        try:
            body = {
                'values': values
            }
            
            result = self.sheets_service.spreadsheets().values().append(
                spreadsheetId=spreadsheet_id, 
                range=range_name,
                valueInputOption='USER_ENTERED', 
                body=body
            ).execute()
            
            updated_cells = result.get('updates', {}).get('updatedCells', 0)
            st.session_state.automation.log(f"Appended {updated_cells} cells to Google Sheet")
            return True
            
        except Exception as e:
            st.session_state.automation.log(f"Failed to append to Google Sheet: {str(e)}", "ERROR")
            return False
    
    def get_sheet_headers(self, spreadsheet_id: str, range_name: str) -> List[str]:
        try:
            result = self.sheets_service.spreadsheets().values().get(
                spreadsheetId=spreadsheet_id,
                range=range_name,
                majorDimension="ROWS"
            ).execute()
            
            values = result.get('values', [])
            if values and len(values) > 0:
                return values[0]
            return []
            
        except Exception as e:
            st.session_state.automation.log(f"Failed to get sheet headers: {str(e)}", "ERROR")
            return []
    
    def clean_number(self, val):
        if isinstance(val, float):
            return round(val, 2)
        return val
    
    def flatten_json(self, extracted_data: Dict) -> List[Dict]:
        flat_header = {
            "grn_date": extracted_data.get("grn_date", ""),
            "po_number": extracted_data.get("po_number", ""),
            "vendor_invoice_number": extracted_data.get("vendor_invoice_number", ""),
            "supplier": extracted_data.get("supplier", ""),
            "shipping_address": extracted_data.get("shipping_address", "")
        }

        merged_rows = []
        for item in extracted_data.get("items", []):
            clean_item = {k: self.clean_number(v) for k, v in item.items()}
            merged_row = {**flat_header, **clean_item}
            merged_rows.append(merged_row)

        return merged_rows
    
    def safe_extract(self, agent, file_path: str, retries: int = 3, wait_time: int = 2):
        for attempt in range(1, retries + 1):
            try:
                result = agent.extract(file_path)
                return result
            except Exception as e:
                st.session_state.automation.log(f"Attempt {attempt} failed for {file_path}: {e}", "ERROR")
                time.sleep(wait_time)
        raise Exception(f"Extraction failed after {retries} attempts for {file_path}")
    
    def process_pdfs(self, drive_folder_id: str, api_key: str, agent_name: str, 
                     spreadsheet_id: str, sheet_range: str = "Sheet1", days_back: int = None, skip_existing: bool = False) -> Dict:
        stats = {
            'total_pdfs': 0,
            'processed_pdfs': 0,
            'failed_pdfs': 0,
            'rows_added': 0
        }
        
        if not LLAMA_AVAILABLE:
            st.session_state.automation.log("LlamaParse not available. Install with: pip install llama-cloud-services", "ERROR")
            return stats
        
        try:
            os.environ["LLAMA_CLOUD_API_KEY"] = api_key
            extractor = LlamaExtract()
            agent = extractor.get_agent(name=agent_name)
            
            if agent is None:
                st.session_state.automation.log(f"Could not find agent '{agent_name}'. Check dashboard.", "ERROR")
                return stats
            
            pdf_files = self.list_drive_files(drive_folder_id, days_back=days_back)
            stats['total_pdfs'] = len(pdf_files)
            
            if not pdf_files:
                st.session_state.automation.log("No PDF files found in the specified folder")
                return stats
            
            if skip_existing:
                existing_ids = st.session_state.automation.get_existing_drive_ids(spreadsheet_id, sheet_range)
                pdf_files = [f for f in pdf_files if f['id'] not in existing_ids]
                st.session_state.automation.log(f"After skipping existing, {len(pdf_files)} PDFs to process")
            
            existing_headers = self.get_sheet_headers(spreadsheet_id, sheet_range)
            
            for i, file in enumerate(pdf_files, 1):
                try:
                    pdf_data = self.download_from_drive(file['id'], file['name'])
                    
                    if not pdf_data:
                        stats['failed_pdfs'] += 1
                        continue
                    
                    temp_path = f"temp_{file['name']}"
                    with open(temp_path, "wb") as f:
                        f.write(pdf_data)
                    
                    result = self.safe_extract(agent, temp_path)
                    extracted_data = result.data
                    
                    os.remove(temp_path)
                    
                    rows = self.flatten_json(extracted_data)
                    for r in rows:
                        r["source_file"] = file['name']
                        r["processed_date"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        r["drive_file_id"] = file['id']
                    
                    if rows:
                        all_keys = set()
                        for row in rows:
                            all_keys.update(row.keys())
                        
                        if existing_headers:
                            headers = existing_headers
                            for key in all_keys:
                                if key not in headers:
                                    headers.append(key)
                        else:
                            headers = list(all_keys)
                        
                        values = []
                        if not existing_headers:
                            values.append(headers)
                            existing_headers = headers
                        
                        for row in rows:
                            row_values = [row.get(h, "") for h in headers]
                            values.append(row_values)
                        
                        success = self.append_to_google_sheet(spreadsheet_id, sheet_range, values)
                        
                        if success:
                            stats['rows_added'] += len(rows)
                    
                    stats['processed_pdfs'] += 1
                    
                except Exception as e:
                    st.session_state.automation.log(f"Failed to process PDF {file['name']}: {str(e)}", "ERROR")
                    stats['failed_pdfs'] += 1
            
            return stats
            
        except Exception as e:
            st.session_state.automation.log(f"LlamaParse processing failed: {str(e)}", "ERROR")
            return stats

class MoreRetailAutomation:
    def __init__(self):
        self.gmail_service = None
        self.drive_service = None
        self.sheets_service = None
        
        self.gmail_scopes = ['https://www.googleapis.com/auth/gmail.readonly']
        self.drive_scopes = ['https://www.googleapis.com/auth/drive']
        self.sheets_scopes = ['https://www.googleapis.com/auth/spreadsheets']
        
        if 'logs' not in st.session_state:
            st.session_state.logs = []
    
    def log(self, message: str, level: str = "INFO"):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = {
            "timestamp": timestamp, 
            "level": level.upper(), 
            "message": message
        }
        
        st.session_state.logs.append(log_entry)
        
        if len(st.session_state.logs) > 100:
            st.session_state.logs = st.session_state.logs[-100:]
    
    def get_logs(self):
        return st.session_state.get('logs', [])
    
    def clear_logs(self):
        st.session_state.logs = []
    
    def authenticate_from_secrets(self, progress_bar, status_text):
        try:
            self.log("Starting authentication process...", "INFO")
            status_text.text("Authenticating with Google APIs...")
            progress_bar.progress(10)
            
            if 'oauth_token' in st.session_state:
                try:
                    combined_scopes = list(set(self.gmail_scopes + self.drive_scopes + self.sheets_scopes))
                    creds = Credentials.from_authorized_user_info(st.session_state.oauth_token, combined_scopes)
                    if creds and creds.valid:
                        progress_bar.progress(50)
                        self.gmail_service = build('gmail', 'v1', credentials=creds)
                        self.drive_service = build('drive', 'v3', credentials=creds)
                        self.sheets_service = build('sheets', 'v4', credentials=creds)
                        progress_bar.progress(100)
                        self.log("Authentication successful using cached token!", "SUCCESS")
                        status_text.text("Authentication successful!")
                        return True
                    elif creds and creds.expired and creds.refresh_token:
                        creds.refresh(Request())
                        st.session_state.oauth_token = json.loads(creds.to_json())
                        self.gmail_service = build('gmail', 'v1', credentials=creds)
                        self.drive_service = build('drive', 'v3', credentials=creds)
                        self.sheets_service = build('sheets', 'v4', credentials=creds)
                        progress_bar.progress(100)
                        self.log("Authentication successful after token refresh!", "SUCCESS")
                        status_text.text("Authentication successful!")
                        return True
                except Exception as e:
                    self.log(f"Cached token invalid: {str(e)}", "WARNING")
            
            if "google" in st.secrets and "credentials_json" in st.secrets["google"]:
                creds_data = json.loads(st.secrets["google"]["credentials_json"])
                combined_scopes = list(set(self.gmail_scopes + self.drive_scopes + self.sheets_scopes))
                
                flow = Flow.from_client_config(
                    client_config=creds_data,
                    scopes=combined_scopes,
                    redirect_uri=st.secrets.get("redirect_uri", "https://your-streamlit-app-url")
                )
                
                auth_url, _ = flow.authorization_url(prompt='consent')
                
                query_params = st.query_params
                if "code" in query_params:
                    try:
                        code = query_params["code"][0]  # Get the first value if it's a list
                        flow.fetch_token(code=code)
                        creds = flow.credentials
                        
                        st.session_state.oauth_token = json.loads(creds.to_json())
                        
                        progress_bar.progress(50)
                        self.gmail_service = build('gmail', 'v1', credentials=creds)
                        self.drive_service = build('drive', 'v3', credentials=creds)
                        self.sheets_service = build('sheets', 'v4', credentials=creds)
                        
                        progress_bar.progress(100)
                        self.log("OAuth authentication successful!", "SUCCESS")
                        status_text.text("Authentication successful!")
                        
                        st.query_params.clear()
                        return True
                    except Exception as e:
                        self.log(f"OAuth authentication failed: {str(e)}", "ERROR")
                        st.error(f"Authentication failed: {str(e)}")
                        return False
                else:
                    st.markdown("### Google Authentication Required")
                    st.markdown(f"[Click here to authorize with Google]({auth_url})")
                    self.log("Waiting for user to authorize application", "INFO")
                    st.info("Click the link above to authorize, you'll be redirected back automatically")
                    st.stop()
            else:
                self.log("Google credentials missing in Streamlit secrets", "ERROR")
                st.error("Google credentials missing in Streamlit secrets")
                return False
                
        except Exception as e:
            self.log(f"Authentication failed: {str(e)}", "ERROR")
            st.error(f"Authentication failed: {str(e)}")
            return False
    
    def get_existing_drive_ids(self, spreadsheet_id: str, sheet_range: str) -> set:
        try:
            result = self.sheets_service.spreadsheets().values().get(
                spreadsheetId=spreadsheet_id,
                range=sheet_range,
                majorDimension="ROWS"
            ).execute()
            
            values = result.get('values', [])
            if not values:
                return set()
            
            headers = values[0]
            if "drive_file_id" not in headers:
                self.log("No 'drive_file_id' column found in sheet", "WARNING")
                return set()
            
            id_index = headers.index("drive_file_id")
            existing_ids = {row[id_index] for row in values[1:] if len(row) > id_index and row[id_index]}
            
            self.log(f"Found {len(existing_ids)} existing file IDs in sheet")
            return existing_ids
            
        except Exception as e:
            self.log(f"Failed to get existing file IDs: {str(e)}", "ERROR")
            return set()

def main():
    st.title("🤖 More Retail Docs Automation")
    st.markdown("### Mail to Drive & Drive to Sheet Processing")
    
    if 'automation' not in st.session_state:
        st.session_state.automation = MoreRetailAutomation()
    
    if 'workflow_running' not in st.session_state:
        st.session_state.workflow_running = False
    
    automation = st.session_state.automation
    
    st.sidebar.header("Configuration")
    
    st.sidebar.subheader("🔐 Authentication")
    auth_status = st.sidebar.empty()
    
    if not automation.gmail_service or not automation.drive_service:
        if st.sidebar.button("🚀 Authenticate with Google", type="primary"):
            progress_bar = st.sidebar.progress(0)
            status_text = st.sidebar.empty()
            
            success = automation.authenticate_from_secrets(progress_bar, status_text)
            if success:
                auth_status.success("✅ Authenticated successfully!")
                st.sidebar.success("Ready to process workflows!")
            else:
                auth_status.error("❌ Authentication failed")
            
            progress_bar.empty()
            status_text.empty()
    else:
        auth_status.success("✅ Already authenticated")
        
        if st.sidebar.button("🔄 Re-authenticate"):
            if 'oauth_token' in st.session_state:
                del st.session_state.oauth_token
            st.session_state.automation = MoreRetailAutomation()
            st.rerun()
    
    tab1, tab2, tab3, tab4 = st.tabs(["📧 Mail to Drive", "📄 Drive to Sheet", "🔗 Combined Workflow", "📋 Logs & Status"])
    
    with tab1:
        st.header("📧 Mail to Drive Workflow")
        st.markdown("Download attachments from Gmail and organize in Google Drive")
        
        if not automation.gmail_service or not automation.drive_service:
            st.warning("⚠️ Please authenticate first using the sidebar")
        else:
            col1, col2 = st.columns(2)
            
            with col1:
                st.subheader("Configuration")
                st.text_input("Sender Email", value=CONFIG['gmail']['sender'], disabled=True)
                st.text_input("Search Keywords", value=CONFIG['gmail']['search_term'], disabled=True)
                st.text_input("Google Drive Folder ID", value=CONFIG['gmail']['gdrive_folder_id'], disabled=True)
                
                st.subheader("Search Parameters")
                gmail_days_back = st.number_input("Days to search back", min_value=1, max_value=365, value=2)
                gmail_max_results = st.number_input("Maximum emails to process", min_value=1, max_value=1000, value=1000)
            
            with col2:
                st.subheader("Description")
                st.info("💡 Searches Gmail, downloads attachments, organizes in Drive by sender, search term, file type.")
            
            if st.button("🚀 Start Mail to Drive", type="primary", disabled=st.session_state.workflow_running):
                st.session_state.workflow_running = True
                
                try:
                    progress_container = st.container()
                    with progress_container:
                        st.subheader("📊 Processing Status")
                        progress_bar = st.progress(0)
                        status_text = st.empty()
                        
                        gmail_automation = GmailGDriveAutomation(
                            automation.gmail_service,
                            automation.drive_service,
                            CONFIG['gmail']['gdrive_folder_id']
                        )
                        
                        status_text.text("Searching emails...")
                        progress_bar.progress(20)
                        
                        emails = gmail_automation.search_emails(
                            CONFIG['gmail']['sender'],
                            CONFIG['gmail']['search_term'],
                            gmail_days_back,
                            gmail_max_results
                        )
                        
                        status_text.text("Processing emails...")
                        progress_bar.progress(50)
                        
                        stats = gmail_automation.process_emails(emails, CONFIG['gmail']['search_term'])
                        
                        progress_bar.progress(100)
                        status_text.text("Completed!")
                        
                        st.success(f"Processed {stats['processed_emails']} emails, uploaded {stats['successful_uploads']} attachments.")
                
                finally:
                    st.session_state.workflow_running = False
    
    with tab2:
        st.header("📄 Drive to Sheet Workflow")
        st.markdown("Extract data from PDFs in Drive using LlamaParse and append to Google Sheets")
        
        if not LLAMA_AVAILABLE:
            st.error("❌ LlamaParse not available. Install with: pip install llama-cloud-services")
        elif not automation.drive_service or not automation.sheets_service:
            st.warning("⚠️ Please authenticate first using the sidebar")
        else:
            col1, col2 = st.columns(2)
            
            with col1:
                st.subheader("Configuration")
                st.text_input("LlamaParse API Key", value="***HIDDEN***", disabled=True)
                st.text_input("LlamaParse Agent Name", value=CONFIG['pdf']['llama_agent'], disabled=True)
                st.text_input("PDF Source Folder ID", value=CONFIG['pdf']['drive_folder_id'], disabled=True)
                st.text_input("Google Sheets Spreadsheet ID", value=CONFIG['pdf']['spreadsheet_id'], disabled=True)
                st.text_input("Sheet Range", value=CONFIG['pdf']['sheet_range'], disabled=True)
                
                st.subheader("Processing Parameters")
                pdf_days_back = st.number_input("Process PDFs from last N days", min_value=1, max_value=365, value=1)
                pdf_skip_existing = st.checkbox("Skip already processed files", value=True)
            
            with col2:
                st.subheader("Description")
                st.info("💡 Fetches PDFs from Drive, extracts data with LlamaParse, appends to Sheets.")
            
            if st.button("🚀 Start Drive to Sheet", type="primary", disabled=st.session_state.workflow_running):
                st.session_state.workflow_running = True
                
                try:
                    progress_container = st.container()
                    with progress_container:
                        st.subheader("📊 Processing Status")
                        progress_bar = st.progress(0)
                        status_text = st.empty()
                        
                        pdf_processor = DrivePDFProcessor(
                            automation.drive_service,
                            automation.sheets_service
                        )
                        
                        status_text.text("Processing PDFs...")
                        progress_bar.progress(50)
                        
                        stats = pdf_processor.process_pdfs(
                            CONFIG['pdf']['drive_folder_id'],
                            CONFIG['pdf']['llama_api_key'],
                            CONFIG['pdf']['llama_agent'],
                            CONFIG['pdf']['spreadsheet_id'],
                            CONFIG['pdf']['sheet_range'],
                            pdf_days_back,
                            pdf_skip_existing
                        )
                        
                        progress_bar.progress(100)
                        status_text.text("Completed!")
                        
                        st.success(f"Processed {stats['processed_pdfs']} PDFs, added {stats['rows_added']} rows.")
                
                finally:
                    st.session_state.workflow_running = False
    
    with tab3:
        st.header("🔗 Combined Workflow")
        st.markdown("Run Mail to Drive first, then Drive to Sheet skipping existing files")
        
        if not automation.gmail_service or not automation.drive_service or not automation.sheets_service:
            st.warning("⚠️ Please authenticate first using the sidebar")
        elif not LLAMA_AVAILABLE:
            st.error("❌ LlamaParse not available.")
        else:
            col1, col2 = st.columns(2)
            
            with col1:
                st.subheader("Parameters")
                combined_days_back = st.number_input("Days back for both", min_value=1, max_value=365, value=2)
                combined_max_emails = st.number_input("Max emails for Mail to Drive", min_value=1, max_value=1000, value=1000)
            
            with col2:
                st.subheader("Description")
                st.info("💡 Runs Mail to Drive, then Drive to Sheet skipping existing file IDs in sheet.")
            
            if st.button("🚀 Start Combined Workflow", type="primary", disabled=st.session_state.workflow_running):
                st.session_state.workflow_running = True
                
                try:
                    progress_container = st.container()
                    with progress_container:
                        st.subheader("📊 Processing Status")
                        progress_bar = st.progress(0)
                        status_text = st.empty()
                        
                        # Mail to Drive
                        status_text.text("Running Mail to Drive...")
                        progress_bar.progress(25)
                        
                        gmail_automation = GmailGDriveAutomation(
                            automation.gmail_service,
                            automation.drive_service,
                            CONFIG['gmail']['gdrive_folder_id']
                        )
                        
                        emails = gmail_automation.search_emails(
                            CONFIG['gmail']['sender'],
                            CONFIG['gmail']['search_term'],
                            combined_days_back,
                            combined_max_emails
                        )
                        
                        gmail_stats = gmail_automation.process_emails(emails, CONFIG['gmail']['search_term'])
                        
                        # Drive to Sheet with skip
                        status_text.text("Running Drive to Sheet (skipping existing)...")
                        progress_bar.progress(50)
                        
                        pdf_processor = DrivePDFProcessor(
                            automation.drive_service,
                            automation.sheets_service
                        )
                        
                        pdf_stats = pdf_processor.process_pdfs(
                            CONFIG['pdf']['drive_folder_id'],
                            CONFIG['pdf']['llama_api_key'],
                            CONFIG['pdf']['llama_agent'],
                            CONFIG['pdf']['spreadsheet_id'],
                            CONFIG['pdf']['sheet_range'],
                            combined_days_back,
                            skip_existing=True
                        )
                        
                        progress_bar.progress(100)
                        status_text.text("Completed!")
                        
                        st.success(f"Mail to Drive: {gmail_stats['successful_uploads']} uploads\nDrive to Sheet: {pdf_stats['processed_pdfs']} PDFs, {pdf_stats['rows_added']} rows.")
                
                finally:
                    st.session_state.workflow_running = False
    
    with tab4:
        st.header("📋 System Logs & Status")
        
        col1, col2, col3 = st.columns(3)
        with col1:
            if st.button("🔄 Refresh Logs"):
                st.rerun()
        with col2:
            if st.button("🗑️ Clear Logs"):
                automation.clear_logs()
                st.success("Logs cleared!")
                st.rerun()
        with col3:
            if st.checkbox("Auto-refresh (5s)", value=False):
                time.sleep(5)
                st.rerun()
        
        logs = automation.get_logs()
        
        if logs:
            st.subheader(f"Recent Activity ({len(logs)} entries)")
            
            for log_entry in reversed(logs[-50:]):
                timestamp = log_entry['timestamp']
                level = log_entry['level']
                message = log_entry['message']
                
                if level == "ERROR":
                    st.error(f"🔴 **{timestamp}** - {message}")
                elif level == "WARNING":
                    st.warning(f"🟡 **{timestamp}** - {message}")
                elif level == "SUCCESS":
                    st.success(f"🟢 **{timestamp}** - {message}")
                else:
                    st.info(f"ℹ️ **{timestamp}** - {message}")
        else:
            st.info("No logs available. Start a workflow to see activity logs here.")
        
        st.subheader("🔧 System Status")
        status_cols = st.columns(2)
        
        with status_cols[0]:
            st.metric("Authentication Status", "✅ Connected" if automation.gmail_service else "❌ Not Connected")
            st.metric("Workflow Status", "🟡 Running" if st.session_state.workflow_running else "🟢 Idle")
        
        with status_cols[1]:
            st.metric("LlamaParse Available", "✅ Available" if LLAMA_AVAILABLE else "❌ Not Installed")
            st.metric("Total Logs", len(logs))

if __name__ == "__main__":
    main()
