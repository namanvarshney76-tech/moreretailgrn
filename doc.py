#!/usr/bin/env python3
"""
Combined Streamlit App for Gmail to Drive and PDF to Excel Workflows
Combines Gmail attachment downloader and LlamaParse PDF processor with real-time tracking
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
    page_title="Combined Automation Workflows",
    page_icon="🤖",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Hardcoded configuration
CONFIG = {
    'gmail': {
        'sender': 'docs@more.in',
        'search_term': 'grn',
        'gdrive_folder_id': '1gZoNjdGarwMD5-Ci3uoqjNZZ8bTNyVoy'
    },
    'pdf': {
        'llama_api_key': 'llx-CXILSN7zQPaaSxBWlwYbxs48oaqDsk2GdgHFpNdn2lQqsXUx',
        'llama_agent': 'More retail Agent',
        'drive_folder_id': '1C251csI1oOeX_skv7mfqpZB0NbyLLd9d',
        'spreadsheet_id': '16y9DAK2tVHgnZNnPeRoSSPPE2NcspW_qqMF8ZR8OOC0',
        'sheet_range': 'mrgrn'
    }
}

class CombinedAutomation:
    def __init__(self):
        self.gmail_service = None
        self.drive_service = None
        self.sheets_service = None
        
        # API scopes
        self.gmail_scopes = ['https://www.googleapis.com/auth/gmail.readonly']
        self.drive_scopes = ['https://www.googleapis.com/auth/drive']
        self.sheets_scopes = ['https://www.googleapis.com/auth/spreadsheets']
        
        # Initialize logs in session state if not exists
        if 'logs' not in st.session_state:
            st.session_state.logs = []
    
    def log(self, message: str, level: str = "INFO"):
        """Add log entry with timestamp to session state"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = {
            "timestamp": timestamp, 
            "level": level.upper(), 
            "message": message
        }
        
        # Add to session state logs
        if 'logs' not in st.session_state:
            st.session_state.logs = []
        
        st.session_state.logs.append(log_entry)
        
        # Keep only last 100 logs to prevent memory issues
        if len(st.session_state.logs) > 100:
            st.session_state.logs = st.session_state.logs[-100:]
    
    def get_logs(self):
        """Get logs from session state"""
        return st.session_state.get('logs', [])
    
    def clear_logs(self):
        """Clear all logs"""
        st.session_state.logs = []
    
    def authenticate_from_secrets(self, progress_bar, status_text):
        """Authenticate using Streamlit secrets with web-based OAuth flow"""
        try:
            self.log("Starting authentication process...", "INFO")
            status_text.text("Authenticating with Google APIs...")
            progress_bar.progress(10)
            
            # Check for existing token in session state
            if 'oauth_token' in st.session_state:
                try:
                    combined_scopes = list(set(self.gmail_scopes + self.drive_scopes + self.sheets_scopes))
                    creds = Credentials.from_authorized_user_info(st.session_state.oauth_token, combined_scopes)
                    if creds and creds.valid:
                        progress_bar.progress(50)
                        # Build services
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
                        # Build services
                        self.gmail_service = build('gmail', 'v1', credentials=creds)
                        self.drive_service = build('drive', 'v3', credentials=creds)
                        self.sheets_service = build('sheets', 'v4', credentials=creds)
                        progress_bar.progress(100)
                        self.log("Authentication successful after token refresh!", "SUCCESS")
                        status_text.text("Authentication successful!")
                        return True
                except Exception as e:
                    self.log(f"Cached token invalid: {str(e)}", "WARNING")
            
            # Use Streamlit secrets for OAuth
            if "google" in st.secrets and "credentials_json" in st.secrets["google"]:
                creds_data = json.loads(st.secrets["google"]["credentials_json"])
                combined_scopes = list(set(self.gmail_scopes + self.drive_scopes + self.sheets_scopes))
                
                # Configure for web application
                flow = Flow.from_client_config(
                    client_config=creds_data,
                    scopes=combined_scopes,
                    redirect_uri=st.secrets.get("redirect_uri", "https://moreretaildoc.streamlit.app/")
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
                        self.sheets_service = build('sheets', 'v4', credentials=creds)
                        
                        progress_bar.progress(100)
                        self.log("OAuth authentication successful!", "SUCCESS")
                        status_text.text("Authentication successful!")
                        
                        # Clear the code from URL
                        st.query_params.clear()
                        return True
                    except Exception as e:
                        self.log(f"OAuth authentication failed: {str(e)}", "ERROR")
                        st.error(f"Authentication failed: {str(e)}")
                        return False
                else:
                    # Show authorization link
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
    
    def search_emails(self, sender: str = "", search_term: str = "", 
                     days_back: int = 7, max_results: int = 50) -> List[Dict]:
        """Search for emails with attachments"""
        try:
            # Build search query
            query_parts = ["has:attachment"]
            
            if sender:
                query_parts.append(f'from:"{sender}"')
            
            if search_term:
                if "," in search_term:
                    keywords = [k.strip() for k in search_term.split(",")]
                    keyword_query = " OR ".join([f'"{k}"' for k in keywords if k])
                    if keyword_query:
                        query_parts.append(f"({keyword_query})")
                else:
                    query_parts.append(f'"{search_term}"')
            
            # Add date filter
            start_date = datetime.now() - timedelta(days=days_back)
            query_parts.append(f"after:{start_date.strftime('%Y/%m/%d')}")
            
            query = " ".join(query_parts)
            self.log(f"Gmail search query: {query}", "INFO")
            
            # Execute search
            result = self.gmail_service.users().messages().list(
                userId='me', q=query, maxResults=max_results
            ).execute()
            
            messages = result.get('messages', [])
            self.log(f"Found {len(messages)} emails matching criteria", "SUCCESS")
            
            return messages
            
        except Exception as e:
            self.log(f"Gmail search failed: {str(e)}", "ERROR")
            return []
    
    def process_gmail_workflow(self, config: dict, progress_callback=None, status_callback=None):
        """Process Gmail attachment download workflow"""
        try:
            if status_callback:
                status_callback("Starting Gmail workflow...")
            
            self.log("Starting Gmail to Drive workflow", "INFO")
            
            # Search for emails
            emails = self.search_emails(
                sender=config['sender'],
                search_term=config['search_term'],
                days_back=config['days_back'],
                max_results=config['max_results']
            )
            
            if progress_callback:
                progress_callback(25)
            
            if not emails:
                self.log("No emails found matching criteria", "WARNING")
                return {'success': True, 'processed': 0}
            
            if status_callback:
                status_callback(f"Found {len(emails)} emails. Processing attachments...")
            
            # Create base folder in Drive
            base_folder_name = "Gmail_Attachments"
            base_folder_id = self._create_drive_folder(base_folder_name, config.get('gdrive_folder_id'))
            
            if not base_folder_id:
                self.log("Failed to create base folder in Google Drive", "ERROR")
                return {'success': False, 'processed': 0}
            
            if progress_callback:
                progress_callback(50)
            
            processed_count = 0
            total_attachments = 0
            
            for i, email in enumerate(emails):
                try:
                    if status_callback:
                        status_callback(f"Processing email {i+1}/{len(emails)}")
                    
                    # Get email details first
                    email_details = self._get_email_details(email['id'])
                    subject = email_details.get('subject', 'No Subject')[:50]
                    sender = email_details.get('sender', 'Unknown')
                    
                    self.log(f"Processing email: {subject} from {sender}", "INFO")
                    
                    # Get full message with payload
                    message = self.gmail_service.users().messages().get(
                        userId='me', id=email['id'], format='full'
                    ).execute()
                    
                    if not message or not message.get('payload'):
                        self.log(f"No payload found for email: {subject}", "WARNING")
                        continue
                    
                    # Extract attachments
                    attachment_count = self._extract_attachments_from_email(
                        email['id'], message['payload'], sender, config, base_folder_id
                    )
                    
                    total_attachments += attachment_count
                    if attachment_count > 0:
                        processed_count += 1
                        self.log(f"Found {attachment_count} attachments in: {subject}", "SUCCESS")
                    
                    if progress_callback:
                        progress = 50 + (i + 1) / len(emails) * 45
                        progress_callback(int(progress))
                    
                except Exception as e:
                    self.log(f"Failed to process email {email.get('id', 'unknown')}: {str(e)}", "ERROR")
            
            if progress_callback:
                progress_callback(100)
            
            if status_callback:
                status_callback(f"Gmail workflow completed! Processed {total_attachments} attachments")
            
            self.log(f"Gmail workflow completed. Processed {total_attachments} attachments from {processed_count} emails", "SUCCESS")
            
            return {'success': True, 'processed': total_attachments}
            
        except Exception as e:
            self.log(f"Gmail workflow failed: {str(e)}", "ERROR")
            return {'success': False, 'processed': 0}
    
    def get_existing_drive_ids(self, spreadsheet_id: str, sheet_range: str) -> set:
        """Get set of existing drive_file_id from Google Sheet"""
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
            
            self.log(f"Found {len(existing_ids)} existing file IDs in sheet", "INFO")
            return existing_ids
            
        except Exception as e:
            self.log(f"Failed to get existing file IDs: {str(e)}", "ERROR")
            return set()
    
    def _get_sheet_headers(self, spreadsheet_id: str, sheet_range: str) -> List[str]:
        """Get existing headers from Google Sheet"""
        try:
            sheet_name = sheet_range.split('!')[0]
            header_range = f"{sheet_name}!A1:AAA1"  # Wide range to cover many columns
            result = self.sheets_service.spreadsheets().values().get(
                spreadsheetId=spreadsheet_id,
                range=header_range,
                majorDimension="ROWS"
            ).execute()
            
            values = result.get('values', [])
            headers = values[0] if values else []
            self.log(f"Fetched {len(headers)} existing headers from sheet", "INFO")
            return headers
            
        except Exception as e:
            self.log(f"Failed to get sheet headers: {str(e)}", "ERROR")
            return []
    
    def _update_sheet_headers(self, spreadsheet_id: str, sheet_range: str, new_headers: List[str]):
        """Update the header row in Google Sheet"""
        try:
            sheet_name = sheet_range.split('!')[0]
            end_col = chr(64 + len(new_headers))
            header_range = f"{sheet_name}!A1:{end_col}1"
            body = {
                'values': [new_headers]
            }
            self.sheets_service.spreadsheets().values().update(
                spreadsheetId=spreadsheet_id,
                range=header_range,
                valueInputOption='USER_ENTERED',
                body=body
            ).execute()
            self.log(f"Updated sheet headers to {len(new_headers)} columns", "SUCCESS")
            return True
            
        except Exception as e:
            self.log(f"Failed to update sheet headers: {str(e)}", "ERROR")
            return False
    
    def process_pdf_workflow(self, config: dict, progress_callback=None, status_callback=None, skip_existing: bool = False):
        """Process PDF to Excel workflow using LlamaParse"""
        try:
            if not LLAMA_AVAILABLE:
                self.log("LlamaParse not available. Install with: pip install llama-cloud-services", "ERROR")
                return {'success': False, 'processed': 0}
            
            if status_callback:
                status_callback("Starting PDF to Excel workflow...")
            
            self.log("Starting PDF to Excel workflow with LlamaParse", "INFO")
            
            # Set up LlamaParse
            os.environ["LLAMA_CLOUD_API_KEY"] = config['llama_api_key']
            extractor = LlamaExtract()
            agent = extractor.get_agent(name=config['llama_agent'])
            
            if agent is None:
                self.log(f"Could not find LlamaParse agent '{config['llama_agent']}'", "ERROR")
                return {'success': False, 'processed': 0}
            
            self.log("LlamaParse agent found successfully", "SUCCESS")
            
            # Get existing headers always
            existing_headers = self._get_sheet_headers(config['spreadsheet_id'], config['sheet_range'])
            
            # Get existing IDs if skipping
            existing_ids = set()
            if skip_existing:
                existing_ids = self.get_existing_drive_ids(config['spreadsheet_id'], config['sheet_range'])
                self.log(f"Skipping {len(existing_ids)} already processed files", "INFO")
            
            # Get PDF files from Drive
            pdf_files = self._list_drive_pdfs(
                config['drive_folder_id'], 
                config['days_back']
            )
            
            # Filter out existing if needed
            if skip_existing:
                pdf_files = [f for f in pdf_files if f['id'] not in existing_ids]
                self.log(f"After filtering, {len(pdf_files)} PDFs to process", "INFO")
            
            # Apply max_files limit
            max_files = config.get('max_files', len(pdf_files))
            pdf_files = pdf_files[:max_files]
            
            if progress_callback:
                progress_callback(25)
            
            if not pdf_files:
                self.log("No PDF files found in the specified folder", "WARNING")
                return {'success': True, 'processed': 0}
            
            if status_callback:
                status_callback(f"Found {len(pdf_files)} PDF files. Processing...")
            
            self.log(f"Found {len(pdf_files)} PDF files to process", "INFO")
            
            processed_count = 0
            total_rows = 0
            
            for i, file in enumerate(pdf_files):
                try:
                    if status_callback:
                        status_callback(f"Processing PDF {i+1}/{len(pdf_files)}: {file['name']}")
                    
                    self.log(f"Processing PDF {i+1}/{len(pdf_files)}: {file['name']}", "INFO")
                    
                    # Download PDF from Drive
                    pdf_data = self._download_from_drive(file['id'], file['name'])
                    
                    if not pdf_data:
                        self.log(f"Failed to download PDF: {file['name']}", "ERROR")
                        continue
                    
                    # Save to temporary file for processing
                    with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as temp_file:
                        temp_file.write(pdf_data)
                        temp_path = temp_file.name
                    
                    try:
                        # Extract data with LlamaParse
                        result = self._safe_extract(agent, temp_path)
                        extracted_data = result.data
                        
                        # Clean up temp file
                        os.unlink(temp_path)
                        
                        # Flatten data for Google Sheets
                        rows = self._flatten_json(extracted_data)
                        for r in rows:
                            r["source_file"] = file['name']
                            r["processed_date"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            r["drive_file_id"] = file['id']
                        
                        if rows:
                            # Prepare data for Google Sheets
                            self.log(f"Preparing {len(rows)} rows for Google Sheets from {file['name']}", "INFO")
                            
                            # Get all unique keys
                            all_keys = set()
                            for row in rows:
                                all_keys.update(row.keys())
                            
                            # Compute new headers
                            headers = existing_headers[:]
                            new_columns = [k for k in sorted(all_keys) if k not in headers]
                            if new_columns:
                                headers += new_columns
                                success = self._update_sheet_headers(
                                    config['spreadsheet_id'],
                                    config['sheet_range'],
                                    headers
                                )
                                if success:
                                    existing_headers = headers
                                else:
                                    continue  # Skip if can't update headers
                            
                            # Prepare values - only rows, no headers
                            values = []
                            if not existing_headers:
                                # First ever append
                                existing_headers = headers
                                values.append(headers)
                            
                            for row in rows:
                                row_values = [row.get(h, "") for h in existing_headers]
                                values.append(row_values)
                            
                            # Append to Google Sheet
                            success = self._append_to_google_sheet(
                                config['spreadsheet_id'], 
                                config['sheet_range'], 
                                values
                            )
                            
                            if success:
                                total_rows += len(rows)
                                self.log(f"Successfully appended {len(rows)} rows from {file['name']}", "SUCCESS")
                            else:
                                self.log(f"Failed to update Google Sheet for {file['name']}", "ERROR")
                        
                        processed_count += 1
                        
                    except Exception as e:
                        # Clean up temp file in case of error
                        if os.path.exists(temp_path):
                            os.unlink(temp_path)
                        raise e
                    
                    if progress_callback:
                        progress = 25 + (i + 1) / len(pdf_files) * 70
                        progress_callback(int(progress))
                    
                except Exception as e:
                    self.log(f"Failed to process PDF {file['name']}: {str(e)}", "ERROR")
            
            if progress_callback:
                progress_callback(100)
            
            if status_callback:
                status_callback(f"PDF workflow completed! Processed {processed_count} files")
            
            self.log(f"PDF workflow completed. Processed {processed_count} PDFs, added {total_rows} rows", "SUCCESS")
            
            return {'success': True, 'processed': processed_count, 'rows_added': total_rows}
            
        except Exception as e:
            self.log(f"PDF workflow failed: {str(e)}", "ERROR")
            return {'success': False, 'processed': 0}
    
    def _get_email_details(self, message_id: str) -> Dict:
        """Get email details including sender and subject"""
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
            self.log(f"Failed to get email details for {message_id}: {str(e)}", "ERROR")
            return {'id': message_id, 'sender': 'Unknown', 'subject': 'Unknown', 'date': ''}
    
    def _create_drive_folder(self, folder_name: str, parent_folder_id: Optional[str] = None) -> str:
        """Create a folder in Google Drive"""
        try:
            # First check if folder already exists
            query = f"name='{folder_name}' and mimeType='application/vnd.google-apps.folder' and trashed=false"
            if parent_folder_id:
                query += f" and '{parent_folder_id}' in parents"
            
            existing = self.drive_service.files().list(q=query, fields='files(id, name)').execute()
            files = existing.get('files', [])
            
            if files:
                # Folder already exists, return its ID
                folder_id = files[0]['id']
                self.log(f"Using existing folder: {folder_name} (ID: {folder_id})", "INFO")
                return folder_id
            
            # Create new folder
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
            self.log(f"Created Google Drive folder: {folder_name} (ID: {folder_id})", "SUCCESS")
            
            return folder_id
            
        except Exception as e:
            self.log(f"Failed to create folder {folder_name}: {str(e)}", "ERROR")
            return ""
    
    def _sanitize_filename(self, filename: str) -> str:
        """Clean up filenames to be safe for all operating systems"""
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
    
    def _classify_extension(self, filename: str) -> str:
        """Categorize file by extension"""
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
    
    def _extract_attachments_from_email(self, message_id: str, payload: Dict, sender: str, config: dict, base_folder_id: str) -> int:
        """Recursively extract all attachments from an email"""
        processed_count = 0
        
        if "parts" in payload:
            for part in payload["parts"]:
                processed_count += self._extract_attachments_from_email(
                    message_id, part, sender, config, base_folder_id
                )
        elif payload.get("filename") and "attachmentId" in payload.get("body", {}):
            filename = payload.get("filename", "")
            
            try:
                # Get attachment data
                attachment_id = payload["body"].get("attachmentId")
                att = self.gmail_service.users().messages().attachments().get(
                    userId='me', messageId=message_id, id=attachment_id
                ).execute()
                
                if not att.get("data"):
                    return 0
                
                file_data = base64.urlsafe_b64decode(att["data"].encode("UTF-8"))
                
                # Create nested folder structure
                sender_email = sender
                if "<" in sender_email and ">" in sender_email:
                    sender_email = sender_email.split("<")[1].split(">")[0].strip()
                
                sender_folder_name = self._sanitize_filename(sender_email)
                search_term = config.get('search_term', 'all-attachments')
                search_folder_name = search_term if search_term else "all-attachments"
                file_type_folder = self._classify_extension(filename)
                
                # Create folder hierarchy
                sender_folder_id = self._create_drive_folder(sender_folder_name, base_folder_id)
                search_folder_id = self._create_drive_folder(search_folder_name, sender_folder_id)
                type_folder_id = self._create_drive_folder(file_type_folder, search_folder_id)
                
                # Upload file
                final_filename = self._sanitize_filename(filename)
                
                # Check if file already exists
                query = f"name='{final_filename}' and '{type_folder_id}' in parents and trashed=false"
                existing = self.drive_service.files().list(q=query, fields='files(id, name)').execute()
                files = existing.get('files', [])
                
                if files:
                    self.log(f"File already exists, skipping: {filename}", "INFO")
                    return 1  # Count as processed but skipped
                
                file_metadata = {
                    'name': final_filename,
                    'parents': [type_folder_id]
                }
                
                media = MediaIoBaseUpload(
                    BytesIO(file_data),
                    mimetype='application/octet-stream',
                    resumable=True
                )
                
                self.drive_service.files().create(
                    body=file_metadata,
                    media_body=media,
                    fields='id'
                ).execute()
                
                self.log(f"Uploaded to Drive: {filename}", "SUCCESS")
                processed_count += 1
                
            except Exception as e:
                self.log(f"Failed to process attachment {filename}: {str(e)}", "ERROR")
        
        return processed_count
    
    def _list_drive_pdfs(self, folder_id: str, days_back: int) -> List[Dict]:
        """List all PDF files in a Google Drive folder, optionally filtered by days back"""
        try:
            # Base query to find all PDF files in the specified folder
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

            self.log(f"Found {len(files)} PDF files in Drive folder", "SUCCESS")
            return files

        except Exception as e:
            self.log(f"Failed to list PDF files in folder: {str(e)}", "ERROR")
            return []
    
    def _download_from_drive(self, file_id: str, file_name: str) -> bytes:
        """Download a file from Google Drive"""
        try:
            request = self.drive_service.files().get_media(fileId=file_id)
            file_data = request.execute()
            self.log(f"Downloaded from Drive: {file_name}", "SUCCESS")
            return file_data
        except Exception as e:
            self.log(f"Failed to download {file_name}: {str(e)}", "ERROR")
            return b""
    
    def _safe_extract(self, agent, file_path: str, retries: int = 3, wait_time: int = 2):
        """Retry-safe extraction to handle server disconnections"""
        for attempt in range(1, retries + 1):
            try:
                self.log(f"Extracting data (attempt {attempt}/{retries})...", "INFO")
                result = agent.extract(file_path)
                self.log("LlamaParse extraction successful", "SUCCESS")
                return result
            except Exception as e:
                self.log(f"Attempt {attempt} failed: {e}", "WARNING")
                time.sleep(wait_time)
        raise Exception(f"Extraction failed after {retries} attempts")
    
    def _flatten_json(self, extracted_data: Dict) -> List[Dict]:
        """Convert extracted_data into row format for Google Sheets"""
        flat_header = {
            "grn_date": extracted_data.get("grn_date", ""),
            "po_number": extracted_data.get("po_number", ""),
            "vendor_invoice_number": extracted_data.get("vendor_invoice_number", ""),
            "supplier": extracted_data.get("supplier", ""),
            "shipping_address": extracted_data.get("shipping_address", "")
        }

        merged_rows = []
        for item in extracted_data.get("items", []):
            clean_item = {k: self._clean_number(v) for k, v in item.items()}
            merged_row = {**flat_header, **clean_item}
            merged_rows.append(merged_row)

        return merged_rows
    
    def _clean_number(self, val):
        """Round floats to 2 decimals, keep integers as-is"""
        if isinstance(val, float):
            return round(val, 2)
        return val
    
    def _append_to_google_sheet(self, spreadsheet_id: str, range_name: str, values: List[List[Any]]):
        """Append data to a Google Sheet"""
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
            self.log(f"Appended {updated_cells} cells to Google Sheet", "SUCCESS")
            return True
            
        except Exception as e:
            self.log(f"Failed to append to Google Sheet: {str(e)}", "ERROR")
            return False


def main():
    """Main Streamlit application"""
    st.title("🤖 More retail DOCS Automation Workflows")
    st.markdown("### Gmail to Drive & PDF to Excel Processing")
    
    # Initialize automation instance in session state
    if 'automation' not in st.session_state:
        st.session_state.automation = CombinedAutomation()
    
    # Initialize workflow running state
    if 'workflow_running' not in st.session_state:
        st.session_state.workflow_running = False
    
    automation = st.session_state.automation
    
    # Sidebar configuration
    st.sidebar.header("Configuration")
    
    # Authentication section
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
        
        # Clear authentication button
        if st.sidebar.button("🔄 Re-authenticate"):
            if 'oauth_token' in st.session_state:
                del st.session_state.oauth_token
            st.session_state.automation = CombinedAutomation()
            st.rerun()
    
    # Main tabs
    tab1, tab2, tab3, tab4 = st.tabs(["📧 Gmail to Drive", "📄 PDF to Excel", "🔗 Combined Workflow", "📋 Logs & Status"])
    
    # Tab 1: Gmail to Drive Workflow
    with tab1:
        st.header("📧 Gmail Attachment Downloader")
        st.markdown("Download attachments from Gmail and organize them in Google Drive")
        
        if not automation.gmail_service or not automation.drive_service:
            st.warning("⚠️ Please authenticate first using the sidebar")
        else:
            col1, col2 = st.columns(2)
            
            with col1:
                st.subheader("Configuration")
                st.text_input("Sender Email", value=CONFIG['gmail']['sender'], disabled=True, key="gmail_sender")
                st.text_input("Search Keywords", value=CONFIG['gmail']['search_term'], disabled=True, key="gmail_search_term")
                st.text_input("Google Drive Folder ID", value=CONFIG['gmail']['gdrive_folder_id'], disabled=True, key="gmail_drive_folder")
                
                st.subheader("Search Parameters")
                gmail_days_back = st.number_input(
                    "Days to search back", 
                    min_value=1, 
                    max_value=365, 
                    value=7,
                    help="How many days back to search",
                    key="gmail_days_back"
                )
                gmail_max_results = st.number_input(
                    "Maximum emails to process", 
                    min_value=1, 
                    max_value=500, 
                    value=50,
                    help="Maximum number of emails to process",
                    key="gmail_max_results"
                )
            
            with col2:
                st.subheader("Description")
                st.info("💡 **How it works:**\n"
                       "1. Searches Gmail for emails with attachments\n"
                       "2. Creates organized folder structure in Drive\n"
                       "3. Downloads and saves attachments by type\n"
                       "4. Avoids duplicates automatically")
            
            # Gmail workflow execution
            if st.button("🚀 Start Gmail Workflow", type="primary", disabled=st.session_state.workflow_running, key="start_gmail_workflow"):
                if st.session_state.workflow_running:
                    st.warning("Another workflow is currently running. Please wait for it to complete.")
                else:
                    st.session_state.workflow_running = True
                    
                    try:
                        config = {
                            'sender': CONFIG['gmail']['sender'],
                            'search_term': CONFIG['gmail']['search_term'],
                            'days_back': gmail_days_back,
                            'max_results': gmail_max_results,
                            'gdrive_folder_id': CONFIG['gmail']['gdrive_folder_id']
                        }
                        
                        progress_container = st.container()
                        with progress_container:
                            st.subheader("📊 Processing Status")
                            progress_bar = st.progress(0)
                            status_text = st.empty()
                            
                            def update_progress(value):
                                progress_bar.progress(value)
                            
                            def update_status(message):
                                status_text.text(message)
                            
                            result = automation.process_gmail_workflow(
                                config, 
                                progress_callback=update_progress,
                                status_callback=update_status
                            )
                            
                            if result['success']:
                                st.success(f"✅ Gmail workflow completed successfully! Processed {result['processed']} attachments.")
                            else:
                                st.error("❌ Gmail workflow failed. Check logs for details.")
                    
                    finally:
                        st.session_state.workflow_running = False
    
    # Tab 2: PDF to Excel Workflow
    with tab2:
        st.header("📄 PDF to Excel Processor")
        st.markdown("Extract structured data from PDFs using LlamaParse and save to Google Sheets")
        
        if not LLAMA_AVAILABLE:
            st.error("❌ LlamaParse not available. Please install: `pip install llama-cloud-services`")
        elif not automation.drive_service or not automation.sheets_service:
            st.warning("⚠️ Please authenticate first using the sidebar")
        else:
            col1, col2 = st.columns(2)
            
            with col1:
                st.subheader("Configuration")
                st.text_input("LlamaParse API Key", value="***HIDDEN***", disabled=True, key="pdf_api_key")
                st.text_input("LlamaParse Agent Name", value=CONFIG['pdf']['llama_agent'], disabled=True, key="pdf_agent_name")
                st.text_input("PDF Source Folder ID", value=CONFIG['pdf']['drive_folder_id'], disabled=True, key="pdf_drive_folder")
                st.text_input("Google Sheets Spreadsheet ID", value=CONFIG['pdf']['spreadsheet_id'], disabled=True, key="pdf_spreadsheet_id")
                st.text_input("Sheet Range", value=CONFIG['pdf']['sheet_range'], disabled=True, key="pdf_sheet_range")
                
                st.subheader("Processing Parameters")
                pdf_days_back = st.number_input(
                    "Process PDFs from last N days", 
                    min_value=1, 
                    max_value=365, 
                    value=7,
                    help="Only process PDFs created in the last N days",
                    key="pdf_days_back"
                )
                pdf_max_files = st.number_input(
                    "Maximum PDFs to process", 
                    min_value=1, 
                    max_value=500, 
                    value=50,
                    help="Maximum number of PDFs to process",
                    key="pdf_max_files"
                )
                pdf_skip_existing = st.checkbox("Skip already processed files", value=True, key="pdf_skip_existing")
            
            with col2:
                st.subheader("Description")
                st.info("💡 **How it works:**\n"
                       "1. Finds PDFs in specified Drive folder\n"
                       "2. Processes each PDF with LlamaParse\n"
                       "3. Extracts structured data\n"
                       "4. Appends results to Google Sheets")
            
            # PDF workflow execution
            if st.button("🚀 Start PDF Workflow", type="primary", disabled=st.session_state.workflow_running, key="start_pdf_workflow"):
                if st.session_state.workflow_running:
                    st.warning("Another workflow is currently running. Please wait for it to complete.")
                else:
                    st.session_state.workflow_running = True
                    
                    try:
                        config = {
                            'llama_api_key': CONFIG['pdf']['llama_api_key'],
                            'llama_agent': CONFIG['pdf']['llama_agent'],
                            'drive_folder_id': CONFIG['pdf']['drive_folder_id'],
                            'spreadsheet_id': CONFIG['pdf']['spreadsheet_id'],
                            'sheet_range': CONFIG['pdf']['sheet_range'],
                            'days_back': pdf_days_back,
                            'max_files': pdf_max_files
                        }
                        
                        progress_container = st.container()
                        with progress_container:
                            st.subheader("📊 Processing Status")
                            progress_bar = st.progress(0)
                            status_text = st.empty()
                            
                            def update_progress(value):
                                progress_bar.progress(value)
                            
                            def update_status(message):
                                status_text.text(message)
                            
                            result = automation.process_pdf_workflow(
                                config, 
                                progress_callback=update_progress,
                                status_callback=update_status,
                                skip_existing=pdf_skip_existing
                            )
                            
                            if result['success']:
                                rows_text = f", added {result['rows_added']} rows" if 'rows_added' in result else ""
                                st.success(f"✅ PDF workflow completed successfully! Processed {result['processed']} files{rows_text}.")
                            else:
                                st.error("❌ PDF workflow failed. Check logs for details.")
                    
                    finally:
                        st.session_state.workflow_running = False
    
    # Tab 3: Combined Workflow
    with tab3:
        st.header("🔗 Combined Workflow")
        st.markdown("Run both Gmail to Drive and PDF to Excel workflows sequentially")
        
        if not automation.gmail_service or not automation.drive_service or not automation.sheets_service:
            st.warning("⚠️ Please authenticate first using the sidebar")
        elif not LLAMA_AVAILABLE:
            st.error("❌ LlamaParse not available. Please install: `pip install llama-cloud-services`")
        else:
            col1, col2 = st.columns(2)
            
            with col1:
                st.subheader("Configuration")
                st.text_input("Gmail Sender", value=CONFIG['gmail']['sender'], disabled=True, key="combined_gmail_sender")
                st.text_input("Gmail Search Keywords", value=CONFIG['gmail']['search_term'], disabled=True, key="combined_gmail_search_term")
                st.text_input("Gmail Drive Folder ID", value=CONFIG['gmail']['gdrive_folder_id'], disabled=True, key="combined_gmail_drive_folder")
                st.text_input("PDF LlamaParse API Key", value="***HIDDEN***", disabled=True, key="combined_pdf_api_key")
                st.text_input("PDF LlamaParse Agent Name", value=CONFIG['pdf']['llama_agent'], disabled=True, key="combined_pdf_agent_name")
                st.text_input("PDF Source Folder ID", value=CONFIG['pdf']['drive_folder_id'], disabled=True, key="combined_pdf_drive_folder")
                st.text_input("Google Sheets Spreadsheet ID", value=CONFIG['pdf']['spreadsheet_id'], disabled=True, key="combined_pdf_spreadsheet_id")
                st.text_input("Sheet Range", value=CONFIG['pdf']['sheet_range'], disabled=True, key="combined_pdf_sheet_range")
                
                st.subheader("Parameters")
                combined_days_back = st.number_input(
                    "Days back for both workflows", 
                    min_value=1, 
                    max_value=365, 
                    value=7,
                    help="Days back for Gmail search and PDF processing",
                    key="combined_days_back"
                )
                combined_max_emails = st.number_input(
                    "Max emails for Gmail", 
                    min_value=1, 
                    max_value=500, 
                    value=50,
                    help="Maximum emails to process in Gmail workflow",
                    key="combined_max_emails"
                )
                combined_max_files = st.number_input(
                    "Max PDFs for processing", 
                    min_value=1, 
                    max_value=500, 
                    value=50,
                    help="Maximum PDFs to process in PDF workflow",
                    key="combined_max_files"
                )
            
            with col2:
                st.subheader("Description")
                st.info("💡 **How it works:**\n"
                       "1. Run Gmail to Drive first\n"
                       "2. Check existing processed PDFs in sheet\n"
                       "3. Run PDF to Excel only on new files\n"
                       "4. Show combined summary")
            
            # Combined workflow execution
            if st.button("🚀 Start Combined Workflow", type="primary", disabled=st.session_state.workflow_running, key="start_combined_workflow"):
                if st.session_state.workflow_running:
                    st.warning("Another workflow is currently running. Please wait for it to complete.")
                else:
                    st.session_state.workflow_running = True
                    
                    try:
                        gmail_config = {
                            'sender': CONFIG['gmail']['sender'],
                            'search_term': CONFIG['gmail']['search_term'],
                            'days_back': combined_days_back,
                            'max_results': combined_max_emails,
                            'gdrive_folder_id': CONFIG['gmail']['gdrive_folder_id']
                        }
                        
                        pdf_config = {
                            'llama_api_key': CONFIG['pdf']['llama_api_key'],
                            'llama_agent': CONFIG['pdf']['llama_agent'],
                            'drive_folder_id': CONFIG['pdf']['drive_folder_id'],
                            'spreadsheet_id': CONFIG['pdf']['spreadsheet_id'],
                            'sheet_range': CONFIG['pdf']['sheet_range'],
                            'days_back': combined_days_back,
                            'max_files': combined_max_files
                        }
                        
                        progress_container = st.container()
                        with progress_container:
                            st.subheader("📊 Processing Status")
                            progress_bar = st.progress(0)
                            status_text = st.empty()
                            
                            def update_progress(value):
                                progress_bar.progress(value)
                            
                            def update_status(message):
                                status_text.text(message)
                            
                            # Run Gmail workflow
                            update_status("Running Gmail to Drive...")
                            gmail_result = automation.process_gmail_workflow(
                                gmail_config, 
                                progress_callback=update_progress,
                                status_callback=update_status
                            )
                            
                            if not gmail_result['success']:
                                st.error("❌ Gmail workflow failed. Stopping combined workflow.")
                                return
                            
                            # Run PDF workflow with skip_existing
                            update_status("Checking existing files and running PDF to Excel...")
                            pdf_result = automation.process_pdf_workflow(
                                pdf_config, 
                                progress_callback=update_progress,
                                status_callback=update_status,
                                skip_existing=True
                            )
                            
                            if pdf_result['success']:
                                summary = f"✅ Combined workflow completed!\n"
                                summary += f"Gmail: Processed {gmail_result['processed']} attachments\n"
                                summary += f"PDF: Processed {pdf_result['processed']} new files, added {pdf_result.get('rows_added', 0)} rows"
                                st.success(summary)
                            else:
                                st.error("❌ PDF workflow failed. Check logs for details.")
                    
                    finally:
                        st.session_state.workflow_running = False
    
    # Tab 4: Logs and Status
    with tab4:
        st.header("📋 System Logs & Status")
        
        col1, col2, col3 = st.columns(3)
        with col1:
            if st.button("🔄 Refresh Logs", key="refresh_logs"):
                st.rerun()
        with col2:
            if st.button("🗑️ Clear Logs", key="clear_logs"):
                automation.clear_logs()
                st.success("Logs cleared!")
                st.rerun()
        with col3:
            if st.checkbox("Auto-refresh (5s)", value=False, key="auto_refresh_logs"):
                time.sleep(5)
                st.rerun()
        
        # Display logs
        logs = automation.get_logs()
        
        if logs:
            st.subheader(f"Recent Activity ({len(logs)} entries)")
            
            # Show logs in reverse chronological order (newest first)
            for log_entry in reversed(logs[-50:]):  # Show last 50 logs
                timestamp = log_entry['timestamp']
                level = log_entry['level']
                message = log_entry['message']
                
                # Color coding based on log level
                if level == "ERROR":
                    st.error(f"🔴 **{timestamp}** - {message}")
                elif level == "WARNING":
                    st.warning(f"🟡 **{timestamp}** - {message}")
                elif level == "SUCCESS":
                    st.success(f"🟢 **{timestamp}** - {message}")
                else:  # INFO
                    st.info(f"ℹ️ **{timestamp}** - {message}")
        else:
            st.info("No logs available. Start a workflow to see activity logs here.")
        
        # System status
        st.subheader("🔧 System Status")
        status_cols = st.columns(2)
        
        with status_cols[0]:
            st.metric("Authentication Status", 
                     "✅ Connected" if automation.gmail_service else "❌ Not Connected")
            st.metric("Workflow Status", 
                     "🟡 Running" if st.session_state.workflow_running else "🟢 Idle")
        
        with status_cols[1]:
            st.metric("LlamaParse Available", 
                     "✅ Available" if LLAMA_AVAILABLE else "❌ Not Installed")
            st.metric("Total Logs", len(logs))


# Run the application
if __name__ == "__main__":
    main()
