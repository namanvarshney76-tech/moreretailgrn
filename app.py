#!/usr/bin/env python3
"""
Streamlit App for Gmail to Google Drive and PDF Processing Automation
"""

import streamlit as st
import os
import json
import time
import logging
import tempfile
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from io import StringIO
import threading
from queue import Queue

# Google API imports
from google.oauth2.credentials import Credentials
from google.oauth2 import service_account
from google_auth_oauthlib.flow import InstalledAppFlow, Flow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# Import your existing classes (simplified versions)
import base64
import re
import uuid
from googleapiclient.http import MediaIoBaseUpload
import io
from datetime import timezone

# LlamaParse import
try:
    from llama_cloud_services import LlamaExtract
    LLAMA_AVAILABLE = True
except ImportError:
    LLAMA_AVAILABLE = False

# Configure Streamlit page
st.set_page_config(
    page_title="Gmail Drive Automation",
    page_icon="📧",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize session state
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
if 'log_messages' not in st.session_state:
    st.session_state.log_messages = []
if 'workflow_running' not in st.session_state:
    st.session_state.workflow_running = False
if 'oauth_token' not in st.session_state:
    st.session_state.oauth_token = None

# Configuration
CONFIGS = {
    'gmail_to_drive': {
        'credentials_path': 'credentials.json',  # Will be created from secrets
        'gdrive_folder_id': '1gZoNjdGarwMD5-Ci3uoqjNZZ8bTNyVoy',
        'sender': 'aws-reports@moreretail.in',
        'search_term': 'in:spam',
    },
    'drive_to_sheet': {
        'credentials_path': 'credentials.json',
        'drive_folder_id': '1XHIFX-Gsb_Mx_AYjoi2NG1vMlvNE5CmQ',
        'llama_api_key': 'llx-DkwQuIwq5RVZk247W0r5WCdywejPI5CybuTDJgAUUcZKNq0A',
        'llama_agent': 'More retail Agent',
        'spreadsheet_id': '16y9DAK2tVHgnZNnPeRoSSPPE2NcspW_qqMF8ZR8OOC0',
        'sheet_range': 'mraws',
    }
}

class StreamlitLogger:
    def __init__(self):
        self.messages = []
    
    def log(self, level, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        formatted_message = f"[{timestamp}] {level}: {message}"
        self.messages.append(formatted_message)
        st.session_state.log_messages.append(formatted_message)
    
    def info(self, message):
        self.log("INFO", message)
    
    def error(self, message):
        self.log("ERROR", message)
    
    def warning(self, message):
        self.log("WARNING", message)

logger = StreamlitLogger()

class GmailGDriveAutomation:
    def __init__(self, credentials_path: str, gdrive_folder_id: Optional[str] = None):
        self.credentials_path = credentials_path
        self.gdrive_folder_id = gdrive_folder_id
        self.gmail_service = None
        self.drive_service = None
        self.gmail_scopes = ['https://www.googleapis.com/auth/gmail.readonly']
        self.drive_scopes = ['https://www.googleapis.com/auth/drive.file']
        
    def authenticate_from_secrets(self, progress_bar, status_text):
        """Authenticate using Streamlit secrets with web-based OAuth flow"""
        try:
            status_text.text("Authenticating with Google APIs...")
            progress_bar.progress(10)
            
            # Check for existing token in session state
            if 'oauth_token' in st.session_state and st.session_state.oauth_token:
                try:
                    combined_scopes = list(set(self.gmail_scopes + self.drive_scopes))
                    creds = Credentials.from_authorized_user_info(st.session_state.oauth_token, combined_scopes)
                    if creds and creds.valid:
                        progress_bar.progress(50)
                        # Build services
                        self.gmail_service = build('gmail', 'v1', credentials=creds)
                        self.drive_service = build('drive', 'v3', credentials=creds)
                        progress_bar.progress(100)
                        status_text.text("Authentication successful!")
                        return True
                    elif creds and creds.expired and creds.refresh_token:
                        creds.refresh(Request())
                        st.session_state.oauth_token = json.loads(creds.to_json())
                        # Build services
                        self.gmail_service = build('gmail', 'v1', credentials=creds)
                        self.drive_service = build('drive', 'v3', credentials=creds)
                        progress_bar.progress(100)
                        status_text.text("Authentication successful!")
                        return True
                except Exception as e:
                    st.info(f"Cached token invalid, requesting new authentication: {str(e)}")
            
            # Use Streamlit secrets for OAuth
            if "google" in st.secrets and "credentials_json" in st.secrets["google"]:
                creds_data = json.loads(st.secrets["google"]["credentials_json"])
                combined_scopes = list(set(self.gmail_scopes + self.drive_scopes))
                
                # Configure for web application
                flow = Flow.from_client_config(
                    client_config=creds_data,
                    scopes=combined_scopes,
                    redirect_uri=st.secrets.get("google", {}).get("redirect_uri", "https://moreretailaws.streamlit.app/")
                )
                
                # Generate authorization URL
                auth_url, _ = flow.authorization_url(prompt='consent')
                
                # Check for callback code
                query_params = st.query_params
                if "code" in query_params:
                    try:
                        code = query_params["code"]
                        flow.fetch_token(code=code)
                        creds = flow.credentials
                        
                        # Save credentials in session state
                        st.session_state.oauth_token = json.loads(creds.to_json())
                        
                        progress_bar.progress(50)
                        # Build services
                        self.gmail_service = build('gmail', 'v1', credentials=creds)
                        self.drive_service = build('drive', 'v3', credentials=creds)
                        
                        progress_bar.progress(100)
                        status_text.text("Authentication successful!")
                        
                        # Clear the code from URL
                        st.query_params.clear()
                        return True
                    except Exception as e:
                        logger.error(f"Authentication failed: {str(e)}")
                        return False
                else:
                    # Show authorization link
                    st.markdown("### Google Authentication Required")
                    st.markdown(f"[Authorize with Google]({auth_url})")
                    st.info("Click the link above to authorize, you'll be redirected back automatically")
                    st.stop()
            else:
                logger.error("Google credentials missing in Streamlit secrets")
                return False
                
        except Exception as e:
            logger.error(f"Authentication failed: {str(e)}")
            return False

    def authenticate(self):
        try:
            with open(self.credentials_path, 'r') as f:
                creds_data = json.load(f)
            
            if 'type' in creds_data and creds_data['type'] == 'service_account':
                gmail_creds = service_account.Credentials.from_service_account_file(
                    self.credentials_path, scopes=self.gmail_scopes)
                drive_creds = service_account.Credentials.from_service_account_file(
                    self.credentials_path, scopes=self.drive_scopes)
            else:
                # Use OAuth authentication from secrets
                progress_bar = st.progress(0)
                status_text = st.empty()
                return self.authenticate_from_secrets(progress_bar, status_text)
            
            self.gmail_service = build('gmail', 'v1', credentials=gmail_creds)
            self.drive_service = build('drive', 'v3', credentials=drive_creds)
            
            logger.info("Successfully authenticated with Gmail and Google Drive")
            return True
            
        except Exception as e:
            logger.error(f"Authentication failed: {str(e)}")
            return False
    
    def _oauth2_authenticate(self, scopes: List[str], service_name: str) -> Credentials:
        creds = None
        token_file = f'token_{service_name}.json'
        
        if os.path.exists(token_file):
            creds = Credentials.from_authorized_user_file(token_file, scopes)
        
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file(
                    self.credentials_path, scopes)
                creds = flow.run_local_server(port=0)
            
            with open(token_file, 'w') as token:
                token.write(creds.to_json())
        
        return creds
    
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
            logger.info(f"Searching Gmail with query: {query}")
            
            result = self.gmail_service.users().messages().list(
                userId='me', q=query, maxResults=max_results
            ).execute()
            
            messages = result.get('messages', [])
            logger.info(f"Found {len(messages)} emails matching criteria")
            
            return messages
            
        except Exception as e:
            logger.error(f"Email search failed: {str(e)}")
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
            logger.error(f"Failed to get email details for {message_id}: {str(e)}")
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
                logger.info(f"Using existing folder: {folder_name}")
                return folder_id
            
            folder_metadata = {
                'name': folder_name,
                'mimeType': 'application/vnd.google-apps.folder'
            }
            
            if parent_folder_id:
                folder_metadata['parents'] = [parent_folder_id]
            
            folder = self.drive_service.files().create(
                body=folder_metadata, fields='id'
            ).execute()
            
            folder_id = folder.get('id')
            logger.info(f"Created Google Drive folder: {folder_name}")
            
            return folder_id
            
        except Exception as e:
            logger.error(f"Failed to create folder {folder_name}: {str(e)}")
            return ""
    
    def upload_to_drive(self, file_data: bytes, filename: str, folder_id: str) -> bool:
        try:
            query = f"name='{filename}' and '{folder_id}' in parents and trashed=false"
            existing = self.drive_service.files().list(q=query, fields='files(id, name)').execute()
            files = existing.get('files', [])
            
            if files:
                logger.info(f"File already exists, skipping: {filename}")
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
                body=file_metadata, media_body=media, fields='id'
            ).execute()
            
            logger.info(f"Uploaded to Drive: {filename}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to upload {filename}: {str(e)}")
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
                logger.info(f"Processed attachment: {filename}")
            
            return success
            
        except Exception as e:
            logger.error(f"Failed to process attachment {part.get('filename', 'unknown')}: {str(e)}")
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
            logger.info("No emails to process")
            return stats
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_folder_name = f"Gmail_Attachments"
        base_folder_id = self.create_drive_folder(base_folder_name, self.gdrive_folder_id)
        if not base_folder_id:
            logger.error("Failed to create base folder in Google Drive")
            return stats
        
        logger.info(f"Processing {len(emails)} emails...")
        
        for i, email in enumerate(emails, 1):
            try:
                logger.info(f"Processing email {i}/{len(emails)}")
                
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
                logger.info(f"Found {attachment_count} attachments in email: {subject}")
                
            except Exception as e:
                logger.error(f"Failed to process email {email.get('id', 'unknown')}: {str(e)}")
                stats['failed_uploads'] += 1
        
        return stats
    
    def run_automation(self, sender: str = "", search_term: str = "", 
                      days_back: int = 7, max_results: int = 50):
        logger.info("Starting Gmail to Google Drive automation")
        logger.info(f"Parameters: sender='{sender}', search_term='{search_term}', days_back={days_back}")
        
        if not self.authenticate():
            return None
        
        emails = self.search_emails(sender, search_term, days_back, max_results)
        
        if not emails:
            logger.info("No emails found matching criteria")
            return {'total_emails': 0, 'processed_emails': 0, 'total_attachments': 0, 'successful_uploads': 0, 'failed_uploads': 0}
        
        stats = self.process_emails(emails, search_term)
        
        logger.info("Gmail to Drive automation complete!")
        logger.info(f"Emails processed: {stats['processed_emails']}/{stats['total_emails']}")
        logger.info(f"Total attachments: {stats['total_attachments']}")
        logger.info(f"Successful uploads: {stats['successful_uploads']}")
        logger.info(f"Failed uploads: {stats['failed_uploads']}")
        
        return stats

class DrivePDFProcessor:
    def __init__(self, credentials_path: str):
        self.credentials_path = credentials_path
        self.drive_service = None
        self.sheets_service = None
        self.drive_scopes = ['https://www.googleapis.com/auth/drive.readonly']
        self.sheets_scopes = ['https://www.googleapis.com/auth/spreadsheets']
        
    def authenticate_from_secrets(self, progress_bar, status_text):
        """Authenticate using Streamlit secrets with web-based OAuth flow"""
        try:
            status_text.text("Authenticating with Google APIs...")
            progress_bar.progress(10)
            
            # Check for existing token in session state
            if 'oauth_token' in st.session_state and st.session_state.oauth_token:
                try:
                    combined_scopes = list(set(self.drive_scopes + self.sheets_scopes))
                    creds = Credentials.from_authorized_user_info(st.session_state.oauth_token, combined_scopes)
                    if creds and creds.valid:
                        progress_bar.progress(50)
                        # Build services
                        self.drive_service = build('drive', 'v3', credentials=creds)
                        self.sheets_service = build('sheets', 'v4', credentials=creds)
                        progress_bar.progress(100)
                        status_text.text("Authentication successful!")
                        return True
                    elif creds and creds.expired and creds.refresh_token:
                        creds.refresh(Request())
                        st.session_state.oauth_token = json.loads(creds.to_json())
                        # Build services
                        self.drive_service = build('drive', 'v3', credentials=creds)
                        self.sheets_service = build('sheets', 'v4', credentials=creds)
                        progress_bar.progress(100)
                        status_text.text("Authentication successful!")
                        return True
                except Exception as e:
                    st.info(f"Cached token invalid, requesting new authentication: {str(e)}")
            
            # Use Streamlit secrets for OAuth
            if "google" in st.secrets and "credentials_json" in st.secrets["google"]:
                creds_data = json.loads(st.secrets["google"]["credentials_json"])
                combined_scopes = list(set(self.drive_scopes + self.sheets_scopes))
                
                # Configure for web application
                flow = Flow.from_client_config(
                    client_config=creds_data,
                    scopes=combined_scopes,
                    redirect_uri=st.secrets.get("google", {}).get("redirect_uri", "https://gmail-drive-automation.streamlit.app/")
                )
                
                # Generate authorization URL
                auth_url, _ = flow.authorization_url(prompt='consent')
                
                # Check for callback code
                query_params = st.query_params
                if "code" in query_params:
                    try:
                        code = query_params["code"]
                        flow.fetch_token(code=code)
                        creds = flow.credentials
                        
                        # Save credentials in session state
                        st.session_state.oauth_token = json.loads(creds.to_json())
                        
                        progress_bar.progress(50)
                        # Build services
                        self.drive_service = build('drive', 'v3', credentials=creds)
                        self.sheets_service = build('sheets', 'v4', credentials=creds)
                        
                        progress_bar.progress(100)
                        status_text.text("Authentication successful!")
                        
                        # Clear the code from URL
                        st.query_params.clear()
                        return True
                    except Exception as e:
                        logger.error(f"Authentication failed: {str(e)}")
                        return False
                else:
                    # Show authorization link
                    st.markdown("### Google Authentication Required")
                    st.markdown(f"[Authorize with Google]({auth_url})")
                    st.info("Click the link above to authorize, you'll be redirected back automatically")
                    st.stop()
            else:
                logger.error("Google credentials missing in Streamlit secrets")
                return False
                
        except Exception as e:
            logger.error(f"Authentication failed: {str(e)}")
            return False

    def authenticate(self):
        try:
            with open(self.credentials_path, 'r') as f:
                creds_data = json.load(f)
            
            if 'type' in creds_data and creds_data['type'] == 'service_account':
                logger.info("Using service account authentication")
                credentials = service_account.Credentials.from_service_account_file(
                    self.credentials_path,
                    scopes=self.drive_scopes + self.sheets_scopes
                )
                
                self.drive_service = build('drive', 'v3', credentials=credentials)
                self.sheets_service = build('sheets', 'v4', credentials=credentials)
                
            else:
                logger.info("Using OAuth2 authentication")
                # Use OAuth authentication from secrets
                progress_bar = st.progress(0)
                status_text = st.empty()
                return self.authenticate_from_secrets(progress_bar, status_text)
            
            logger.info("Successfully authenticated with Google Drive and Sheets")
            return True
            
        except Exception as e:
            logger.error(f"Authentication failed: {str(e)}")
            return False
    
    def _oauth2_authenticate(self, scopes: List[str], service_name: str) -> Credentials:
        creds = None
        token_file = f'token_{service_name}.json'
        
        if os.path.exists(token_file):
            creds = Credentials.from_authorized_user_file(token_file, scopes)
        
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file(
                    self.credentials_path, scopes)
                creds = flow.run_local_server(port=0)
            
            with open(token_file, 'w') as token:
                token.write(creds.to_json())
        
        return creds
    
    def list_drive_files(self, folder_id: str, days_back: int = None) -> List[Dict]:
        try:
            query = f"'{folder_id}' in parents and mimeType='application/pdf' and trashed=false"
            
            if days_back is not None:
                today_utc = datetime.now(timezone.utc)
                start_date = today_utc - timedelta(days=days_back - 1)
                start_date = start_date.replace(hour=0, minute=0, second=0, microsecond=0)
                start_str = start_date.strftime('%Y-%m-%dT%H:%M:%SZ')
                query += f" and createdTime >= '{start_str}'"
                logger.info(f"Applying date filter: createdTime >= {start_str}")
            
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

            logger.info(f"Found {len(files)} PDF files in folder {folder_id}")
            
            for file in files:
                logger.info(f"Found file: {file['name']} (ID: {file['id']})")
            
            return files

        except Exception as e:
            logger.error(f"Failed to list files in folder {folder_id}: {str(e)}")
            return []
    
    def download_from_drive(self, file_id: str, file_name: str) -> bytes:
        try:
            logger.info(f"Downloading: {file_name}")
            request = self.drive_service.files().get_media(fileId=file_id)
            file_data = request.execute()
            logger.info(f"Downloaded: {file_name}")
            return file_data
        except Exception as e:
            logger.error(f"Failed to download {file_name}: {str(e)}")
            return b""
    
    def append_to_google_sheet(self, spreadsheet_id: str, range_name: str, values: List[List]):
        try:
            body = {'values': values}
            
            result = self.sheets_service.spreadsheets().values().append(
                spreadsheetId=spreadsheet_id, 
                range=range_name,
                valueInputOption='USER_ENTERED', 
                body=body
            ).execute()
            
            updated_cells = result.get('updates', {}).get('updatedCells', 0)
            logger.info(f"Appended {updated_cells} cells to Google Sheet")
            return True
            
        except Exception as e:
            logger.error(f"Failed to append to Google Sheet: {str(e)}")
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
            logger.error(f"Failed to get sheet headers: {str(e)}")
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
                logger.info(f"Extracting data (attempt {attempt}/{retries})...")
                result = agent.extract(file_path)
                logger.info("Extraction successful")
                return result
            except Exception as e:
                logger.error(f"Attempt {attempt} failed for {file_path}: {e}")
                time.sleep(wait_time)
        raise Exception(f"Extraction failed after {retries} attempts for {file_path}")
    
    def process_pdfs(self, drive_folder_id: str, api_key: str, agent_name: str, 
                    spreadsheet_id: str, sheet_range: str = "Sheet1", days_back: int = None) -> Dict:
        stats = {
            'total_pdfs': 0,
            'processed_pdfs': 0,
            'failed_pdfs': 0,
            'rows_added': 0
        }
        
        if not LLAMA_AVAILABLE:
            logger.error("LlamaParse not available. Install with: pip install llama-cloud-services")
            return stats
        
        try:
            logger.info("Setting up LlamaParse...")
            os.environ["LLAMA_CLOUD_API_KEY"] = api_key
            extractor = LlamaExtract()
            agent = extractor.get_agent(name=agent_name)
            
            if agent is None:
                logger.error(f"Could not find agent '{agent_name}'. Check dashboard.")
                return stats
            
            logger.info("LlamaParse agent found")
            
            logger.info(f"Searching for PDFs in folder ID: {drive_folder_id}")
            pdf_files = self.list_drive_files(drive_folder_id, days_back=days_back)
            stats['total_pdfs'] = len(pdf_files)
            
            if not pdf_files:
                logger.info("No PDF files found in the specified folder")
                return stats
            
            logger.info(f"Found {len(pdf_files)} PDF files to process")
            
            logger.info("Checking existing sheet headers...")
            existing_headers = self.get_sheet_headers(spreadsheet_id, sheet_range)
            
            if not existing_headers:
                logger.info("No existing headers found, will create new headers after first PDF")
            
            for i, file in enumerate(pdf_files, 1):
                try:
                    logger.info(f"Processing PDF {i}/{len(pdf_files)}: {file['name']}")
                    
                    pdf_data = self.download_from_drive(file['id'], file['name'])
                    
                    if not pdf_data:
                        logger.error(f"Failed to download PDF: {file['name']}")
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
                        logger.info(f"Preparing {len(rows)} rows for Google Sheets...")
                        
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
                        
                        logger.info(f"Saving {len(rows)} rows from {file['name']} to Google Sheets...")
                        success = self.append_to_google_sheet(spreadsheet_id, sheet_range, values)
                        
                        if success:
                            stats['rows_added'] += len(rows)
                            logger.info(f"Successfully appended {len(rows)} rows from {file['name']} to Google Sheet")
                        else:
                            logger.error(f"Failed to update Google Sheet for {file['name']}")
                    
                    stats['processed_pdfs'] += 1
                    logger.info(f"Successfully processed: {file['name']}")
                    logger.info(f"Extracted {len(rows)} rows from this PDF")
                    
                except Exception as e:
                    logger.error(f"Error processing {file['name']}: {e}")
                    stats['failed_pdfs'] += 1
            
            return stats
            
        except Exception as e:
            logger.error(f"LlamaParse processing failed: {str(e)}")
            return stats

def authenticate_user():
    """Handle user authentication"""
    st.subheader("🔐 Authentication")
    
    # Check if credentials are available in secrets
    if "google" not in st.secrets or "credentials_json" not in st.secrets["google"]:
        st.error("Google credentials not found in Streamlit secrets. Please add your credentials.json content to secrets.")
        st.info("Go to Streamlit Cloud dashboard > App settings > Secrets and add your Google credentials JSON content under the [google] section with 'credentials_json' key.")
        return False
    
    try:
        # Load credentials from secrets
        credentials_content = st.secrets["google"]["credentials_json"]
        with open('credentials.json', 'w') as f:
            f.write(credentials_content)  # Write as string, since it's multiline
        
        st.success("✅ Credentials loaded successfully from Streamlit secrets!")
        st.session_state.authenticated = True
        return True
        
    except Exception as e:
        st.error(f"Failed to load credentials: {str(e)}")
        return False

def display_config(workflow_type: str, config: Dict):
    """Display configuration for each workflow"""
    st.subheader(f"📋 {workflow_type.replace('_', ' ').title()} Configuration")
    
    # Create two columns for better layout
    col1, col2 = st.columns(2)
    
    with col1:
        for key, value in config.items():
            if key == 'credentials_path':
                st.text_input("Credentials Path", value=value, disabled=True, key=f"{workflow_type}_{key}")
            elif 'api_key' in key.lower():
                # Hide API keys for security
                st.text_input(key.replace('_', ' ').title(), value="*" * 20, disabled=True, key=f"{workflow_type}_{key}")
            else:
                st.text_input(key.replace('_', ' ').title(), value=str(value), disabled=True, key=f"{workflow_type}_{key}")

def run_gmail_to_drive_workflow(days_back: int, max_results: int):
    """Run Gmail to Drive workflow"""
    st.session_state.workflow_running = True
    st.session_state.log_messages = []  # Clear previous logs
    
    try:
        config = CONFIGS['gmail_to_drive']
        automation = GmailGDriveAutomation(
            credentials_path=config['credentials_path'],
            gdrive_folder_id=config['gdrive_folder_id']
        )
        
        stats = automation.run_automation(
            sender=config['sender'],
            search_term=config['search_term'],
            days_back=days_back,
            max_results=max_results
        )
        
        return stats
        
    except Exception as e:
        logger.error(f"Gmail to Drive workflow failed: {str(e)}")
        return None
    finally:
        st.session_state.workflow_running = False

def run_drive_to_sheet_workflow(days_back: int):
    """Run Drive to Sheet workflow"""
    st.session_state.workflow_running = True
    st.session_state.log_messages = []  # Clear previous logs
    
    try:
        config = CONFIGS['drive_to_sheet']
        processor = DrivePDFProcessor(credentials_path=config['credentials_path'])
        
        if not processor.authenticate():
            logger.error("Authentication failed for Drive to Sheet workflow")
            return None
        
        stats = processor.process_pdfs(
            drive_folder_id=config['drive_folder_id'],
            api_key=config['llama_api_key'],
            agent_name=config['llama_agent'],
            spreadsheet_id=config['spreadsheet_id'],
            sheet_range=config['sheet_range'],
            days_back=days_back
        )
        
        return stats
        
    except Exception as e:
        logger.error(f"Drive to Sheet workflow failed: {str(e)}")
        return None
    finally:
        st.session_state.workflow_running = False

def run_combined_workflow(gmail_days_back: int, max_results: int, sheet_days_back: int):
    """Run combined workflow"""
    st.session_state.workflow_running = True
    st.session_state.log_messages = []  # Clear previous logs
    
    try:
        logger.info("🚀 Starting Combined Workflow")
        logger.info("Step 1: Running Gmail to Drive workflow...")
        
        # Step 1: Gmail to Drive
        gmail_stats = run_gmail_to_drive_workflow(gmail_days_back, max_results)
        
        if gmail_stats is None:
            logger.error("Gmail to Drive workflow failed, stopping combined workflow")
            return None, None
        
        logger.info("Step 1 completed successfully!")
        logger.info("Step 2: Running Drive to Sheet workflow...")
        
        # Step 2: Drive to Sheet
        sheet_stats = run_drive_to_sheet_workflow(sheet_days_back)
        
        if sheet_stats is None:
            logger.error("Drive to Sheet workflow failed")
            return gmail_stats, None
        
        logger.info("🎉 Combined workflow completed successfully!")
        return gmail_stats, sheet_stats
        
    except Exception as e:
        logger.error(f"Combined workflow failed: {str(e)}")
        return None, None
    finally:
        st.session_state.workflow_running = False

def display_workflow_results(stats: Dict, workflow_name: str):
    """Display workflow results in a nice format"""
    if stats is None:
        st.error(f"❌ {workflow_name} failed to complete")
        return
    
    st.success(f"✅ {workflow_name} completed successfully!")
    
    # Create metrics display
    if 'total_emails' in stats:  # Gmail to Drive stats
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Emails Processed", f"{stats['processed_emails']}/{stats['total_emails']}")
        with col2:
            st.metric("Total Attachments", stats['total_attachments'])
        with col3:
            st.metric("Successful Uploads", stats['successful_uploads'])
        with col4:
            st.metric("Failed Uploads", stats['failed_uploads'])
    
    elif 'total_pdfs' in stats:  # Drive to Sheet stats
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("PDFs Processed", f"{stats['processed_pdfs']}/{stats['total_pdfs']}")
        with col2:
            st.metric("Failed PDFs", stats['failed_pdfs'])
        with col3:
            st.metric("Rows Added", stats['rows_added'])
        with col4:
            st.metric("Success Rate", f"{(stats['processed_pdfs']/max(stats['total_pdfs'], 1)*100):.1f}%")

def main():
    """Main Streamlit app"""
    st.title("📧 Gmail Drive Automation")
    st.markdown("Automated workflows for Gmail to Google Drive and PDF processing")
    
    # Authentication check
    if not st.session_state.authenticated:
        if not authenticate_user():
            st.stop()
    
    # Create tabs
    tab1, tab2, tab3, tab4 = st.tabs(["📧 Gmail to Drive", "📄 Drive to Excel", "🔄 Combined Workflow", "📋 Logs"])
    
    # Tab 1: Gmail to Drive
    with tab1:
        st.header("📧 Gmail to Google Drive Workflow")
        
        # Display configuration
        display_config("gmail_to_drive", CONFIGS['gmail_to_drive'])
        
        st.markdown("---")
        st.subheader("⚙️ Workflow Parameters")
        
        # User-configurable parameters
        col1, col2 = st.columns(2)
        with col1:
            gmail_days_back = st.number_input(
                "Days Back to Search", 
                min_value=1, 
                max_value=365, 
                value=7, 
                help="How many days back to search for emails",
                key="gmail_days_back"
            )
        with col2:
            gmail_max_results = st.number_input(
                "Max Results", 
                min_value=1, 
                max_value=1000, 
                value=50, 
                help="Maximum number of emails to process",
                key="gmail_max_results"
            )
        
        st.markdown("---")
        
        # Start workflow button
        if not st.session_state.workflow_running:
            if st.button("🚀 Start Gmail to Drive Workflow", type="primary", key="start_gmail"):
                with st.spinner("Running Gmail to Drive workflow..."):
                    stats = run_gmail_to_drive_workflow(gmail_days_back, gmail_max_results)
                    display_workflow_results(stats, "Gmail to Drive Workflow")
        else:
            st.warning("⏳ Workflow is currently running...")
    
    # Tab 2: Drive to Excel
    with tab2:
        st.header("📄 Drive to Excel Workflow")
        
        if not LLAMA_AVAILABLE:
            st.error("❌ LlamaParse not available. Please install: `pip install llama-cloud-services`")
            st.stop()
        
        # Display configuration
        display_config("drive_to_sheet", CONFIGS['drive_to_sheet'])
        
        st.markdown("---")
        st.subheader("⚙️ Workflow Parameters")
        
        # User-configurable parameters
        sheet_days_back = st.number_input(
            "Days Back to Process", 
            min_value=1, 
            max_value=365, 
            value=1, 
            help="How many days back to process PDFs (1 = today only)",
            key="sheet_days_back"
        )
        
        st.markdown("---")
        
        # Start workflow button
        if not st.session_state.workflow_running:
            if st.button("🚀 Start Drive to Excel Workflow", type="primary", key="start_sheet"):
                with st.spinner("Running Drive to Excel workflow..."):
                    stats = run_drive_to_sheet_workflow(sheet_days_back)
                    display_workflow_results(stats, "Drive to Excel Workflow")
        else:
            st.warning("⏳ Workflow is currently running...")
    
    # Tab 3: Combined Workflow
    with tab3:
        st.header("🔄 Combined Workflow")
        st.info("This workflow runs Gmail to Drive first, then Drive to Excel automatically.")
        
        # Display both configurations
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("### 📧 Gmail to Drive Config")
            display_config("gmail_to_drive", CONFIGS['gmail_to_drive'])
        
        with col2:
            st.markdown("### 📄 Drive to Excel Config")
            display_config("drive_to_sheet", CONFIGS['drive_to_sheet'])
        
        st.markdown("---")
        st.subheader("⚙️ Workflow Parameters")
        
        # Parameters for both workflows
        col1, col2, col3 = st.columns(3)
        with col1:
            combined_gmail_days = st.number_input(
                "Gmail Days Back", 
                min_value=1, 
                max_value=365, 
                value=7, 
                key="combined_gmail_days"
            )
        with col2:
            combined_max_results = st.number_input(
                "Gmail Max Results", 
                min_value=1, 
                max_value=1000, 
                value=50, 
                key="combined_max_results"
            )
        with col3:
            combined_sheet_days = st.number_input(
                "PDF Processing Days Back", 
                min_value=1, 
                max_value=365, 
                value=1, 
                key="combined_sheet_days"
            )
        
        st.markdown("---")
        
        # Start combined workflow button
        if not st.session_state.workflow_running:
            if st.button("🚀 Start Combined Workflow", type="primary", key="start_combined"):
                with st.spinner("Running combined workflow..."):
                    gmail_stats, sheet_stats = run_combined_workflow(
                        combined_gmail_days, combined_max_results, combined_sheet_days
                    )
                    
                    # Display results for both workflows
                    if gmail_stats:
                        st.subheader("📧 Gmail to Drive Results")
                        display_workflow_results(gmail_stats, "Gmail to Drive")
                    
                    if sheet_stats:
                        st.subheader("📄 Drive to Excel Results")
                        display_workflow_results(sheet_stats, "Drive to Excel")
        else:
            st.warning("⏳ Combined workflow is currently running...")
    
    # Tab 4: Logs
    with tab4:
        st.header("📋 Workflow Logs")
        
        if st.button("🔄 Refresh Logs"):
            st.rerun()
        
        if st.button("🗑️ Clear Logs"):
            st.session_state.log_messages = []
            st.rerun()
        
        st.markdown("---")
        
        # Display logs
        if st.session_state.log_messages:
            log_text = "\n".join(st.session_state.log_messages)
            st.text_area("Logs", value=log_text, height=400, disabled=True)
            
            # Download logs button
            st.download_button(
                label="📥 Download Logs",
                data=log_text,
                file_name=f"workflow_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                mime="text/plain"
            )
        else:
            st.info("No logs available. Run a workflow to see logs here.")
        
        # Auto-refresh logs when workflow is running
        if st.session_state.workflow_running:
            time.sleep(2)
            st.rerun()

if __name__ == "__main__":
    main()
