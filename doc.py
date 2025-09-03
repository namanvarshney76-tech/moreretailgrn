import streamlit as st
import os
import json
import base64
import time
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any
import threading
import queue
import psutil
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from googleapiclient.http import MediaIoBaseUpload
import io
import re

# Try to import LlamaParse
try:
    from llama_cloud_services import LlamaExtract
    LLAMA_AVAILABLE = True
except ImportError:
    LLAMA_AVAILABLE = False

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Hardcoded configs (from scripts)
GMAIL_CONFIG = {
    'gdrive_folder_id': '1gZoNjdGarwMD5-Ci3uoqjNZZ8bTNyVoy',
    'sender': 'aws-reports@moreretail.in',
    'search_term': 'in:spam ',
    'days_back': 10,  # Editable
    'max_results': 1000  # Editable
}

PDF_CONFIG = {
    'drive_folder_id': '1XHIFX-Gsb_Mx_AYjoi2NG1vMlvNE5CmQ',
    'llama_api_key': 'llx-DkwQuIwq5RVZk247W0r5WCdywejPI5CybuTDJgAUUcZKNq0A',
    'llama_agent': 'More retail Agent',
    'spreadsheet_id': '16y9DAK2tVHgnZNnPeRoSSPPE2NcspW_qqMF8ZR8OOC0',
    'sheet_range': 'mraws',
    'days_back': 1  # Editable
}

class GmailGDriveAutomation:
    # (Copied and adapted from gmailtodrive.py, with progress_queue added)
    def __init__(self, gdrive_folder_id: Optional[str] = None):
        self.gdrive_folder_id = gdrive_folder_id
        self.gmail_service = None
        self.drive_service = None
        self.gmail_scopes = ['https://www.googleapis.com/auth/gmail.readonly']
        self.drive_scopes = ['https://www.googleapis.com/auth/drive.file']

    def authenticate(self, creds):
        self.gmail_service = build('gmail', 'v1', credentials=creds)
        self.drive_service = build('drive', 'v3', credentials=creds)

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
            "pdf": "PDFs", "doc": "Documents", "docx": "Documents", "txt": "Documents",
            "xls": "Spreadsheets", "xlsx": "Spreadsheets", "csv": "Spreadsheets",
            "jpg": "Images", "jpeg": "Images", "png": "Images", "gif": "Images",
            "ppt": "Presentations", "pptx": "Presentations",
            "zip": "Archives", "rar": "Archives", "7z": "Archives",
        }
        return type_map.get(ext, "Other")

    def search_emails(self, sender: str = "", search_term: str = "", 
                      days_back: int = 7, max_results: int = 50, progress_queue: queue.Queue = None) -> List[Dict]:
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
            progress_queue.put({'type': 'info', 'text': f"Searching Gmail with query: {query}"})
            result = self.gmail_service.users().messages().list(
                userId='me', q=query, maxResults=max_results
            ).execute()
            messages = result.get('messages', [])
            progress_queue.put({'type': 'info', 'text': f"Found {len(messages)} emails"})
            return messages
        except Exception as e:
            progress_queue.put({'type': 'error', 'text': f"Email search failed: {str(e)}"})
            return []

    def get_email_details(self, message_id: str, progress_queue: queue.Queue) -> Dict:
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
            progress_queue.put({'type': 'error', 'text': f"Failed to get email details: {str(e)}"})
            return {}

    def create_drive_folder(self, folder_name: str, parent_folder_id: Optional[str] = None, progress_queue: queue.Queue = None) -> str:
        try:
            query = f"name='{folder_name}' and mimeType='application/vnd.google-apps.folder' and trashed=false"
            if parent_folder_id:
                query += f" and '{parent_folder_id}' in parents"
            existing = self.drive_service.files().list(q=query, fields='files(id, name)').execute()
            files = existing.get('files', [])
            if files:
                return files[0]['id']
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
            return folder.get('id')
        except Exception as e:
            progress_queue.put({'type': 'error', 'text': f"Failed to create folder {folder_name}: {str(e)}"})
            return ""

    def upload_to_drive(self, file_data: bytes, filename: str, folder_id: str, progress_queue: queue.Queue) -> bool:
        try:
            query = f"name='{filename}' and '{folder_id}' in parents and trashed=false"
            existing = self.drive_service.files().list(q=query, fields='files(id, name)').execute()
            if existing.get('files', []):
                progress_queue.put({'type': 'info', 'text': f"File already exists, skipping: {filename}"})
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
            self.drive_service.files().create(
                body=file_metadata,
                media_body=media,
                fields='id'
            ).execute()
            progress_queue.put({'type': 'success', 'text': f"Uploaded: {filename}"})
            return True
        except Exception as e:
            progress_queue.put({'type': 'error', 'text': f"Failed to upload {filename}: {str(e)}"})
            return False

    def process_attachment(self, message_id: str, part: Dict, sender_info: Dict, 
                           search_term: str, base_folder_id: str, progress_queue: queue.Queue) -> bool:
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
            if "<" in sender_email:
                sender_email = sender_email.split("<")[1].split(">")[0].strip()
            sender_folder_name = self.sanitize_filename(sender_email)
            search_folder_name = search_term if search_term else "all-attachments"
            file_type_folder = self.classify_extension(filename)
            sender_folder_id = self.create_drive_folder(sender_folder_name, base_folder_id, progress_queue)
            search_folder_id = self.create_drive_folder(search_folder_name, sender_folder_id, progress_queue)
            type_folder_id = self.create_drive_folder(file_type_folder, search_folder_id, progress_queue)
            return self.upload_to_drive(file_data, final_filename, type_folder_id, progress_queue)
        except Exception as e:
            progress_queue.put({'type': 'error', 'text': f"Failed to process attachment {part.get('filename', 'unknown')}: {str(e)}"})
            return False

    def extract_attachments_from_email(self, message_id: str, payload: Dict, 
                                       sender_info: Dict, search_term: str, 
                                       base_folder_id: str, progress_queue: queue.Queue) -> int:
        processed_count = 0
        if "parts" in payload:
            for part in payload["parts"]:
                processed_count += self.extract_attachments_from_email(
                    message_id, part, sender_info, search_term, base_folder_id, progress_queue
                )
        elif payload.get("filename") and "attachmentId" in payload.get("body", {}):
            if self.process_attachment(message_id, payload, sender_info, search_term, base_folder_id, progress_queue):
                processed_count += 1
        return processed_count

    def process_emails(self, emails: List[Dict], search_term: str = "", progress_queue: queue.Queue = None) -> Dict:
        stats = {
            'total_emails': len(emails),
            'processed_emails': 0,
            'total_attachments': 0,
            'successful_uploads': 0,
            'failed_uploads': 0
        }
        if not emails:
            progress_queue.put({'type': 'warning', 'text': "No emails to process"})
            return stats
        base_folder_name = "Gmail_Attachments"
        base_folder_id = self.create_drive_folder(base_folder_name, self.gdrive_folder_id, progress_queue)
        if not base_folder_id:
            progress_queue.put({'type': 'error', 'text': "Failed to create base folder"})
            return stats
        for i, email in enumerate(emails, 1):
            try:
                progress_queue.put({'type': 'info', 'text': f"Processing email {i}/{len(emails)}"})
                sender_info = self.get_email_details(email['id'], progress_queue)
                if not sender_info:
                    continue
                message = self.gmail_service.users().messages().get(
                    userId='me', id=email['id']
                ).execute()
                if not message or not message.get('payload'):
                    continue
                attachment_count = self.extract_attachments_from_email(
                    email['id'], message['payload'], sender_info, search_term, base_folder_id, progress_queue
                )
                stats['total_attachments'] += attachment_count
                stats['successful_uploads'] += attachment_count
                stats['processed_emails'] += 1
            except Exception as e:
                progress_queue.put({'type': 'error', 'text': f"Failed to process email: {str(e)}"})
                stats['failed_uploads'] += 1
        return stats

    def run_automation(self, sender: str, search_term: str, days_back: int, max_results: int, progress_queue: queue.Queue):
        progress_queue.put({'type': 'info', 'text': "Starting Gmail to Drive workflow"})
        emails = self.search_emails(sender, search_term, days_back, max_results, progress_queue)
        stats = self.process_emails(emails, search_term, progress_queue)
        progress_queue.put({'type': 'summary', 'stats': stats})
        progress_queue.put({'type': 'done'})

class DrivePDFProcessor:
    # (Copied and adapted from pdftoexcel.py, with progress_queue and duplicate check added)
    def __init__(self):
        self.drive_service = None
        self.sheets_service = None
        self.drive_scopes = ['https://www.googleapis.com/auth/drive.readonly']
        self.sheets_scopes = ['https://www.googleapis.com/auth/spreadsheets']

    def authenticate(self, creds):
        self.drive_service = build('drive', 'v3', credentials=creds)
        self.sheets_service = build('sheets', 'v4', credentials=creds)

    def list_drive_files(self, folder_id: str, days_back: int = None, progress_queue: queue.Queue = None) -> List[Dict]:
        try:
            query = f"'{folder_id}' in parents and mimeType='application/pdf' and trashed=false"
            if days_back is not None:
                today_utc = datetime.now(timezone.utc)
                start_date = today_utc - timedelta(days=days_back - 1)
                start_date = start_date.replace(hour=0, minute=0, second=0, microsecond=0)
                start_str = start_date.strftime('%Y-%m-%dT%H:%M:%SZ')
                query += f" and createdTime >= '{start_str}'"
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
            progress_queue.put({'type': 'info', 'text': f"Found {len(files)} PDF files"})
            return files
        except Exception as e:
            progress_queue.put({'type': 'error', 'text': f"Failed to list files: {str(e)}"})
            return []

    def download_from_drive(self, file_id: str, file_name: str, progress_queue: queue.Queue) -> bytes:
        try:
            progress_queue.put({'type': 'info', 'text': f"Downloading: {file_name}"})
            request = self.drive_service.files().get_media(fileId=file_id)
            file_data = request.execute()
            return file_data
        except Exception as e:
            progress_queue.put({'type': 'error', 'text': f"Failed to download {file_name}: {str(e)}"})
            return b""

    def append_to_google_sheet(self, spreadsheet_id: str, range_name: str, values: List[List[Any]], progress_queue: queue.Queue):
        try:
            body = {'values': values}
            result = self.sheets_service.spreadsheets().values().append(
                spreadsheetId=spreadsheet_id, 
                range=range_name,
                valueInputOption='USER_ENTERED', 
                body=body
            ).execute()
            updated_cells = result.get('updates', {}).get('updatedCells', 0)
            progress_queue.put({'type': 'info', 'text': f"Appended {updated_cells} cells"})
            return True
        except Exception as e:
            progress_queue.put({'type': 'error', 'text': f"Failed to append to sheet: {str(e)}"})
            return False

    def get_sheet_headers(self, spreadsheet_id: str, range_name: str, progress_queue: queue.Queue) -> List[str]:
        try:
            result = self.sheets_service.spreadsheets().values().get(
                spreadsheetId=spreadsheet_id,
                range=range_name,
                majorDimension="ROWS"
            ).execute()
            values = result.get('values', [])
            return values[0] if values else []
        except Exception as e:
            progress_queue.put({'type': 'info', 'text': f"No headers found: {str(e)}"})
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

    def safe_extract(self, agent, file_path: str, retries: int = 3, wait_time: int = 2, progress_queue: queue.Queue = None):
        for attempt in range(1, retries + 1):
            try:
                progress_queue.put({'type': 'info', 'text': f"Extracting data (attempt {attempt}/{retries})"})
                result = agent.extract(file_path)
                return result
            except Exception as e:
                progress_queue.put({'type': 'warning', 'text': f"Attempt {attempt} failed: {e}"})
                time.sleep(wait_time)
        raise Exception("Extraction failed after retries")

    def check_duplicates(self, spreadsheet_id: str, sheet_range: str, file_id: str, progress_queue: queue.Queue) -> int:
        try:
            data = self.sheets_service.spreadsheets().values().get(
                spreadsheetId=spreadsheet_id,
                range=sheet_range
            ).execute().get('values', [])
            if not data or len(data) < 2:
                return 0
            headers = data[0]
            if 'drive_file_id' not in headers:
                return 0
            col_idx = headers.index('drive_file_id')
            duplicates = sum(1 for row in data[1:] if len(row) > col_idx and row[col_idx] == file_id)
            progress_queue.put({'type': 'info', 'text': f"Found {duplicates} duplicate entries for file {file_id}"})
            return duplicates
        except Exception as e:
            progress_queue.put({'type': 'error', 'text': f"Failed to check duplicates: {str(e)}"})
            return 0

    def process_pdfs(self, drive_folder_id: str, api_key: str, agent_name: str, 
                     spreadsheet_id: str, sheet_range: str = "Sheet1", days_back: int = None, progress_queue: queue.Queue = None) -> Dict:
        stats = {
            'total_pdfs': 0,
            'processed_pdfs': 0,
            'failed_pdfs': 0,
            'rows_added': 0,
            'duplicates': 0
        }
        if not LLAMA_AVAILABLE:
            progress_queue.put({'type': 'error', 'text': "LlamaParse not available"})
            return stats
        try:
            os.environ["LLAMA_CLOUD_API_KEY"] = api_key
            extractor = LlamaExtract()
            agent = extractor.get_agent(name=agent_name)
            if agent is None:
                progress_queue.put({'type': 'error', 'text': f"Agent '{agent_name}' not found"})
                return stats
            pdf_files = self.list_drive_files(drive_folder_id, days_back, progress_queue)
            stats['total_pdfs'] = len(pdf_files)
            if not pdf_files:
                progress_queue.put({'type': 'warning', 'text': "No PDF files found"})
                return stats
            existing_headers = self.get_sheet_headers(spreadsheet_id, sheet_range, progress_queue)
            for i, file in enumerate(pdf_files, 1):
                try:
                    progress_queue.put({'type': 'info', 'text': f"Processing PDF {i}/{len(pdf_files)}: {file['name']}"})
                    duplicates = self.check_duplicates(spreadsheet_id, sheet_range, file['id'], progress_queue)
                    stats['duplicates'] += duplicates
                    if duplicates > 0:
                        progress_queue.put({'type': 'info', 'text': f"Skipping duplicate file: {file['name']}"})
                        continue
                    pdf_data = self.download_from_drive(file['id'], file['name'], progress_queue)
                    if not pdf_data:
                        stats['failed_pdfs'] += 1
                        continue
                    temp_path = f"temp_{file['name']}"
                    with open(temp_path, "wb") as f:
                        f.write(pdf_data)
                    result = self.safe_extract(agent, temp_path, progress_queue=progress_queue)
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
                        success = self.append_to_google_sheet(spreadsheet_id, sheet_range, values, progress_queue)
                        if success:
                            stats['rows_added'] += len(rows)
                            stats['processed_pdfs'] += 1
                        else:
                            stats['failed_pdfs'] += 1
                except Exception as e:
                    progress_queue.put({'type': 'error', 'text': f"Failed to process {file['name']}: {str(e)}"})
                    stats['failed_pdfs'] += 1
            return stats
        except Exception as e:
            progress_queue.put({'type': 'error', 'text': f"PDF processing failed: {str(e)}"})
            return stats

    def run_automation(self, progress_queue: queue.Queue):
        progress_queue.put({'type': 'info', 'text': "Starting Drive to Excel workflow"})
        stats = self.process_pdfs(
            PDF_CONFIG['drive_folder_id'], PDF_CONFIG['llama_api_key'], PDF_CONFIG['llama_agent'],
            PDF_CONFIG['spreadsheet_id'], PDF_CONFIG['sheet_range'], PDF_CONFIG['days_back'], progress_queue
        )
        progress_queue.put({'type': 'summary', 'stats': stats})
        progress_queue.put({'type': 'done'})

def run_workflow_in_background(gmail_automation, pdf_processor, workflow_type, progress_queue, creds):
    gmail_automation.authenticate(creds)
    pdf_processor.authenticate(creds)
    if workflow_type == "gmail":
        gmail_automation.run_automation(
            GMAIL_CONFIG['sender'], GMAIL_CONFIG['search_term'], GMAIL_CONFIG['days_back'], GMAIL_CONFIG['max_results'], progress_queue
        )
    elif workflow_type == "pdf":
        pdf_processor.run_automation(progress_queue)
    elif workflow_type == "combined":
        progress_queue.put({'type': 'info', 'text': "Running combined workflow: Gmail to Drive first"})
        gmail_automation.run_automation(
            GMAIL_CONFIG['sender'], GMAIL_CONFIG['search_term'], GMAIL_CONFIG['days_back'], GMAIL_CONFIG['max_results'], progress_queue
        )
        progress_queue.put({'type': 'info', 'text': "Now running Drive to Excel"})
        pdf_processor.run_automation(progress_queue)
        progress_queue.put({'type': 'done'})

def authenticate_from_secrets():
    if 'oauth_token' in st.session_state:
        try:
            combined_scopes = ['https://www.googleapis.com/auth/gmail.readonly', 'https://www.googleapis.com/auth/drive.file', 'https://www.googleapis.com/auth/drive.readonly', 'https://www.googleapis.com/auth/spreadsheets']
            creds = Credentials.from_authorized_user_info(st.session_state.oauth_token, combined_scopes)
            if creds and creds.valid:
                return creds
        except:
            pass
    if "google" in st.secrets and "credentials_json" in st.secrets["google"]:
        creds_data = json.loads(st.secrets["google"]["credentials_json"])
        combined_scopes = ['https://www.googleapis.com/auth/gmail.readonly', 'https://www.googleapis.com/auth/drive.file', 'https://www.googleapis.com/auth/drive.readonly', 'https://www.googleapis.com/auth/spreadsheets']
        flow = Flow.from_client_config(
            client_config=creds_data,
            scopes=combined_scopes,
            redirect_uri="https://your-app-url.streamlit.app/"  # Replace with your Streamlit app URL
        )
        query_params = st.query_params
        if "code" in query_params:
            try:
                code = query_params["code"][0]
                flow.fetch_token(code=code)
                creds = flow.credentials
                st.session_state.oauth_token = json.loads(creds.to_json())
                st.query_params.clear()
                return creds
            except Exception as e:
                st.error(f"Authentication failed: {str(e)}")
                return None
        else:
            auth_url, _ = flow.authorization_url(prompt='consent')
            st.markdown(f"[Authorize with Google]({auth_url})")
            st.info("Click the link to authorize.")
            st.stop()
    else:
        st.error("Google credentials missing in Streamlit secrets")
        st.stop()
    return None

def main():
    st.set_page_config(page_title="Gmail & PDF Automation", layout="wide")
    st.title("Gmail to Drive & Drive to Excel Automation")

    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    if 'creds' not in st.session_state:
        st.session_state.creds = None
    if 'workflow_state' not in st.session_state:
        st.session_state.workflow_state = {
            'running': False,
            'type': None,
            'logs': [],
            'summary': None,
            'queue': queue.Queue(),
            'thread': None
        }
    if 'gmail_days_back' not in st.session_state:
        st.session_state.gmail_days_back = GMAIL_CONFIG['days_back']
    if 'gmail_max_results' not in st.session_state:
        st.session_state.gmail_max_results = GMAIL_CONFIG['max_results']
    if 'pdf_days_back' not in st.session_state:
        st.session_state.pdf_days_back = PDF_CONFIG['days_back']

    if not st.session_state.authenticated:
        st.header("Authentication Required")
        creds = authenticate_from_secrets()
        if creds:
            st.session_state.creds = creds
            st.session_state.authenticated = True
            st.rerun()

    if st.session_state.authenticated:
        tab1, tab2, tab3, tab4 = st.tabs(["Gmail to Drive", "Drive to Excel", "Combined", "Logs"])

        with tab1:
            st.subheader("Gmail to Drive Config")
            st.json({k: v for k, v in GMAIL_CONFIG.items() if k not in ['days_back', 'max_results']})
            st.session_state.gmail_days_back = st.number_input("Days Back", value=st.session_state.gmail_days_back, min_value=1)
            st.session_state.gmail_max_results = st.number_input("Max Results", value=st.session_state.gmail_max_results, min_value=1)
            if st.button("Start Gmail to Drive") and not st.session_state.workflow_state['running']:
                st.session_state.workflow_state['type'] = "gmail"
                st.session_state.workflow_state['running'] = True
                st.session_state.workflow_state['logs'] = []
                st.session_state.workflow_state['summary'] = None
                gmail_automation = GmailGDriveAutomation(GMAIL_CONFIG['gdrive_folder_id'])
                pdf_processor = DrivePDFProcessor()
                thread = threading.Thread(
                    target=run_workflow_in_background,
                    args=(gmail_automation, pdf_processor, "gmail", st.session_state.workflow_state['queue'], st.session_state.creds)
                )
                thread.start()
                st.session_state.workflow_state['thread'] = thread

        with tab2:
            st.subheader("Drive to Excel Config")
            st.json({k: v for k, v in PDF_CONFIG.items() if k != 'days_back'})
            st.session_state.pdf_days_back = st.number_input("Days Back", value=st.session_state.pdf_days_back, min_value=1)
            if st.button("Start Drive to Excel") and not st.session_state.workflow_state['running']:
                PDF_CONFIG['days_back'] = st.session_state.pdf_days_back
                st.session_state.workflow_state['type'] = "pdf"
                st.session_state.workflow_state['running'] = True
                st.session_state.workflow_state['logs'] = []
                st.session_state.workflow_state['summary'] = None
                gmail_automation = GmailGDriveAutomation()
                pdf_processor = DrivePDFProcessor()
                thread = threading.Thread(
                    target=run_workflow_in_background,
                    args=(gmail_automation, pdf_processor, "pdf", st.session_state.workflow_state['queue'], st.session_state.creds)
                )
                thread.start()
                st.session_state.workflow_state['thread'] = thread

        with tab3:
            st.subheader("Combined Config")
            st.subheader("Gmail to Drive Part")
            st.json({k: v for k, v in GMAIL_CONFIG.items() if k not in ['days_back', 'max_results']})
            st.session_state.gmail_days_back = st.number_input("Gmail Days Back", value=st.session_state.gmail_days_back, min_value=1, key="combined_gmail_days")
            st.session_state.gmail_max_results = st.number_input("Gmail Max Results", value=st.session_state.gmail_max_results, min_value=1, key="combined_gmail_max")
            st.subheader("Drive to Excel Part")
            st.json({k: v for k, v in PDF_CONFIG.items() if k != 'days_back'})
            st.session_state.pdf_days_back = st.number_input("PDF Days Back", value=st.session_state.pdf_days_back, min_value=1, key="combined_pdf_days")
            if st.button("Start Combined Workflow") and not st.session_state.workflow_state['running']:
                GMAIL_CONFIG['days_back'] = st.session_state.gmail_days_back
                GMAIL_CONFIG['max_results'] = st.session_state.gmail_max_results
                PDF_CONFIG['days_back'] = st.session_state.pdf_days_back
                st.session_state.workflow_state['type'] = "combined"
                st.session_state.workflow_state['running'] = True
                st.session_state.workflow_state['logs'] = []
                st.session_state.workflow_state['summary'] = None
                gmail_automation = GmailGDriveAutomation(GMAIL_CONFIG['gdrive_folder_id'])
                pdf_processor = DrivePDFProcessor()
                thread = threading.Thread(
                    target=run_workflow_in_background,
                    args=(gmail_automation, pdf_processor, "combined", st.session_state.workflow_state['queue'], st.session_state.creds)
                )
                thread.start()
                st.session_state.workflow_state['thread'] = thread

        with tab4:
            st.subheader("Real-time Logs")
            log_container = st.empty()
            summary_container = st.empty()

        # Poll queue and update logs/summary
        if st.session_state.workflow_state['running']:
            while not st.session_state.workflow_state['queue'].empty():
                msg = st.session_state.workflow_state['queue'].get()
                if msg['type'] == 'info':
                    st.session_state.workflow_state['logs'].append(f"INFO: {msg['text']}")
                elif msg['type'] == 'warning':
                    st.session_state.workflow_state['logs'].append(f"WARNING: {msg['text']}")
                elif msg['type'] == 'error':
                    st.session_state.workflow_state['logs'].append(f"ERROR: {msg['text']}")
                elif msg['type'] == 'success':
                    st.session_state.workflow_state['logs'].append(f"SUCCESS: {msg['text']}")
                elif msg['type'] == 'summary':
                    st.session_state.workflow_state['summary'] = msg['stats']
                elif msg['type'] == 'done':
                    st.session_state.workflow_state['running'] = False

            with tab4:
                log_container.text_area("Logs", "\n".join(st.session_state.workflow_state['logs'][-100:]), height=300)
                if st.session_state.workflow_state['summary']:
                    summary = st.session_state.workflow_state['summary']
                    summary_text = f"Processed Files: {summary.get('processed_emails', summary.get('processed_pdfs', 0))}\n"
                    summary_text += f"Failed Files: {summary.get('failed_uploads', summary.get('failed_pdfs', 0))}\n"
                    summary_text += f"Rows Appended: {summary.get('rows_added', 0)}\n"
                    summary_text += f"Duplicates: {summary.get('duplicates', summary.get('total_attachments', 0) - summary.get('successful_uploads', 0))}\n"
                    summary_container.text(summary_text)

            if not st.session_state.workflow_state['running']:
                st.session_state.workflow_state['thread'].join()
                st.success("Workflow completed!")

if __name__ == "__main__":
    main()
