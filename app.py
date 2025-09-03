#!/usr/bin/env python3
"""
Streamlit App for More Retail AWS Automation Workflows
Combines Gmail attachment downloader and PDF processor with real-time tracking
Fixed version with better error handling and folder management
"""
import streamlit as st
import os
import json
import base64
import tempfile
import time
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from io import StringIO
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
from streamlit_autorefresh import st_autorefresh

# Try to import LlamaParse
try:
    from llama_cloud_services import LlamaExtract
    LLAMA_AVAILABLE = True
except ImportError:
    LLAMA_AVAILABLE = False

# Configure Streamlit page
st.set_page_config(
    page_title="More Retail AWS Automation",
    page_icon="🛒",
    layout="wide",
    initial_sidebar_state="expanded"
)

class MoreRetailAutomation:
    def __init__(self):
        self.gmail_service = None
        self.drive_service = None
        self.sheets_service = None
        self.processed_state_file = "more_retail_processed_state.json"
        self.processed_emails = set()
        self.processed_pdfs = set()
        self.authentication_complete = False
        
        # Statistics tracking
        self.stats = {
            'rows_appended': 0,
            'duplicates_found': 0,
            'files_processed': 0,
            'files_failed': 0
        }
        
        # Load processed state
        self._load_processed_state()
        
        # API scopes
        self.gmail_scopes = ['https://www.googleapis.com/auth/gmail.readonly']
        self.drive_scopes = ['https://www.googleapis.com/auth/drive.file']
        self.sheets_scopes = ['https://www.googleapis.com/auth/spreadsheets']
    
    def _load_processed_state(self):
        """Load previously processed email and PDF IDs from file"""
        try:
            if os.path.exists(self.processed_state_file):
                with open(self.processed_state_file, 'r') as f:
                    state = json.load(f)
                    self.processed_emails = set(state.get('emails', []))
                    self.processed_pdfs = set(state.get('pdfs', []))
        except Exception as e:
            pass
    
    def _save_processed_state(self):
        """Save processed email and PDF IDs to file"""
        try:
            state = {
                'emails': list(self.processed_emails),
                'pdfs': list(self.processed_pdfs)
            }
            with open(self.processed_state_file, 'w') as f:
                json.dump(state, f)
        except Exception as e:
            pass
    
    def _check_memory(self, progress_queue: queue.Queue):
        """Check memory usage to prevent crashes"""
        try:
            process = psutil.Process()
            mem_info = process.memory_info()
            if mem_info.rss > 0.8 * psutil.virtual_memory().total:  # 80% of total memory
                progress_queue.put({'type': 'error', 'text': "Memory usage too high, stopping to prevent crash"})
                return False
            return True
        except:
            return True  # If we can't check memory, assume it's fine
    
    def authenticate_from_secrets(self, progress_bar, status_text, progress_queue: queue.Queue):
        """Authenticate using Streamlit secrets with web-based OAuth flow"""
        try:
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
                        status_text.text("Authentication successful!")
                        self.authentication_complete = True
                        return True
                except Exception as e:
                    progress_queue.put({'type': 'info', 'text': f"Cached token invalid, requesting new authentication: {str(e)}"})
            
            # Use Streamlit secrets for OAuth
            if "google" in st.secrets and "credentials_json" in st.secrets["google"]:
                creds_data = json.loads(st.secrets["google"]["credentials_json"])
                combined_scopes = list(set(self.gmail_scopes + self.drive_scopes + self.sheets_scopes))
                
                # Configure for web application
                flow = Flow.from_client_config(
                    client_config=creds_data,
                    scopes=combined_scopes,
                    redirect_uri="https://moreretailaws.streamlit.app/"  # Update with your actual URL
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
                        status_text.text("Authentication successful!")
                        
                        self.authentication_complete = True
                        
                        # Clear the code from URL
                        st.query_params.clear()
                        return True
                    except Exception as e:
                        progress_queue.put({'type': 'error', 'text': f"Authentication failed: {str(e)}"})
                        return False
                else:
                    # Show authorization link
                    st.markdown("### Google Authentication Required")
                    st.markdown(f"[Authorize with Google]({auth_url})")
                    st.info("Click the link above to authorize, you'll be redirected back automatically")
                    st.stop()
            else:
                progress_queue.put({'type': 'error', 'text': "Google credentials missing in Streamlit secrets"})
                return False
                
        except Exception as e:
            progress_queue.put({'type': 'error', 'text': f"Authentication failed: {str(e)}"})
            return False
    
    def search_emails(self, sender: str = "", search_term: str = "",
                     days_back: int = 7, max_results: int = 50, progress_queue: queue.Queue = None) -> List[Dict]:
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
            progress_queue.put({'type': 'info', 'text': f"Gmail search query: {query}"})
            
            # Execute search
            result = self.gmail_service.users().messages().list(
                userId='me', q=query, maxResults=max_results
            ).execute()
            
            messages = result.get('messages', [])
            progress_queue.put({'type': 'info', 'text': f"Gmail search returned {len(messages)} messages with attachments"})
            
            return messages
            
        except Exception as e:
            progress_queue.put({'type': 'error', 'text': f"Gmail search failed: {str(e)}"})
            return []
    
    def process_gmail_workflow(self, config: dict, progress_queue: queue.Queue):
        """Process Gmail attachment download workflow"""
        try:
            if not self._check_memory(progress_queue):
                progress_queue.put({'type': 'done', 'result': {'success': False, 'processed': 0}})
                return
            
            progress_queue.put({'type': 'status', 'text': "Starting Gmail workflow..."})
            progress_queue.put({'type': 'progress', 'value': 10})
            
            # Search for emails
            emails = self.search_emails(
                sender=config['sender'],
                search_term=config['search_term'],
                days_back=config['days_back'],
                max_results=config['max_results'],
                progress_queue=progress_queue
            )
            
            progress_queue.put({'type': 'progress', 'value': 25})
            
            if not emails:
                progress_queue.put({'type': 'warning', 'text': "No emails found matching criteria"})
                progress_queue.put({'type': 'done', 'result': {'success': True, 'processed': 0}})
                return
            
            progress_queue.put({'type': 'status', 'text': f"Found {len(emails)} emails. Processing attachments..."})
            
            # Create base folder in Drive using improved method
            base_folder_name = "Gmail_Attachments"
            base_folder_id = self._get_or_create_drive_folder(base_folder_name, config.get('gdrive_folder_id'), progress_queue)
            
            if not base_folder_id:
                progress_queue.put({'type': 'error', 'text': "Failed to create/find base folder in Google Drive"})
                progress_queue.put({'type': 'done', 'result': {'success': False, 'processed': 0}})
                return
            
            progress_queue.put({'type': 'progress', 'value': 50})
            
            processed_count = 0
            total_attachments = 0
            
            for i, email in enumerate(emails):
                # Skip already processed emails
                if email['id'] in self.processed_emails:
                    progress_queue.put({'type': 'info', 'text': f"Skipping already processed email ID: {email['id']}"})
                    continue
                
                try:
                    progress_queue.put({'type': 'status', 'text': f"Processing email {i+1}/{len(emails)}"})
                    
                    # Get email details
                    email_details = self._get_email_details(email['id'], progress_queue)
                    subject = email_details.get('subject', 'No Subject')[:50]
                    sender = email_details.get('sender', 'Unknown')
                    
                    progress_queue.put({'type': 'info', 'text': f"Processing: {subject} from {sender}"})
                    
                    # Get full message with payload
                    message = self.gmail_service.users().messages().get(
                        userId='me', id=email['id'], format='full'
                    ).execute()
                    
                    if not message or not message.get('payload'):
                        progress_queue.put({'type': 'warning', 'text': f"No payload found for email: {subject}"})
                        continue
                    
                    # Extract attachments
                    attachment_count = self._extract_attachments_from_email(
                        email['id'], message['payload'], config, base_folder_id, progress_queue
                    )
                    
                    total_attachments += attachment_count
                    if attachment_count > 0:
                        processed_count += 1
                        self.processed_emails.add(email['id'])
                        self._save_processed_state()
                        progress_queue.put({'type': 'success', 'text': f"Downloaded {attachment_count} attachments from: {subject}"})
                    else:
                        progress_queue.put({'type': 'info', 'text': f"No PDF attachments found in: {subject}"})
                    
                    progress = 50 + (i + 1) / len(emails) * 45
                    progress_queue.put({'type': 'progress', 'value': int(progress)})
                    
                except Exception as e:
                    progress_queue.put({'type': 'error', 'text': f"Failed to process email {email.get('id', 'unknown')}: {str(e)}"})
            
            progress_queue.put({'type': 'progress', 'value': 100})
            progress_queue.put({'type': 'status', 'text': f"Gmail workflow completed!"})
            progress_queue.put({'type': 'success', 'text': f"Successfully downloaded {total_attachments} PDF attachments from {processed_count} emails"})
            progress_queue.put({'type': 'done', 'result': {'success': True, 'processed': total_attachments}})
            
        except Exception as e:
            progress_queue.put({'type': 'error', 'text': f"Gmail workflow failed: {str(e)}"})
            progress_queue.put({'type': 'done', 'result': {'success': False, 'processed': 0}})
    
    def _get_email_details(self, message_id: str, progress_queue: queue.Queue) -> Dict:
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
            progress_queue.put({'type': 'warning', 'text': f"Failed to get email details for {message_id}: {str(e)}"})
            return {'id': message_id, 'sender': 'Unknown', 'subject': 'Unknown', 'date': ''}
    
    def _get_or_create_drive_folder(self, folder_name: str, parent_folder_id: Optional[str] = None, progress_queue: queue.Queue = None) -> str:
        """Get existing folder or create new one in Google Drive"""
        try:
            # Build query to find existing folder
            query = f"name='{folder_name}' and mimeType='application/vnd.google-apps.folder' and trashed=false"
            if parent_folder_id:
                query += f" and '{parent_folder_id}' in parents"
            
            # Search for existing folder
            existing = self.drive_service.files().list(q=query, fields='files(id, name)').execute()
            files = existing.get('files', [])
            
            if files:
                folder_id = files[0]['id']
                progress_queue.put({'type': 'info', 'text': f"Using existing folder: {folder_name}"})
                return folder_id
            
            # Create new folder if it doesn't exist
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
            progress_queue.put({'type': 'info', 'text': f"Created new folder: {folder_name}"})
            return folder_id
            
        except Exception as e:
            progress_queue.put({'type': 'error', 'text': f"Failed to get/create folder {folder_name}: {str(e)}"})
            return ""
    
    def _extract_attachments_from_email(self, message_id: str, payload: Dict, config: dict, base_folder_id: str, progress_queue: queue.Queue) -> int:
        """Extract PDF attachments from email with proper folder structure"""
        processed_count = 0
        
        if "parts" in payload:
            for part in payload["parts"]:
                processed_count += self._extract_attachments_from_email(
                    message_id, part, config, base_folder_id, progress_queue
                )
        elif payload.get("filename") and "attachmentId" in payload.get("body", {}):
            filename = payload.get("filename", "")
            
            # Only process PDF files for More Retail
            if not filename.lower().endswith('.pdf'):
                return 0
            
            try:
                # Get attachment data
                attachment_id = payload["body"].get("attachmentId")
                att = self.gmail_service.users().messages().attachments().get(
                    userId='me', messageId=message_id, id=attachment_id
                ).execute()
                
                file_data = base64.urlsafe_b64decode(att["data"].encode("UTF-8"))
                
                # Create folder structure: base -> sender -> search_term -> PDFs
                sender_folder_name = self._clean_folder_name(config['sender'])
                sender_folder_id = self._get_or_create_drive_folder(sender_folder_name, base_folder_id, progress_queue)
                
                search_term = config.get('search_term', 'general').strip()
                if not search_term:
                    search_term = 'general'
                search_folder_name = self._clean_folder_name(search_term)
                search_folder_id = self._get_or_create_drive_folder(search_folder_name, sender_folder_id, progress_queue)
                
                pdfs_folder_id = self._get_or_create_drive_folder("PDFs", search_folder_id, progress_queue)
                
                # Clean filename and make it unique
                clean_filename = self._sanitize_filename(filename)
                unique_filename = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{clean_filename}"
                
                # Check if similar file already exists to avoid duplicates
                if not self._file_exists_in_folder(clean_filename, pdfs_folder_id):
                    # Upload to Drive
                    file_metadata = {
                        'name': unique_filename,
                        'parents': [pdfs_folder_id]
                    }
                    
                    media = MediaIoBaseUpload(
                        io.BytesIO(file_data),
                        mimetype='application/pdf',
                        resumable=True
                    )
                    
                    uploaded_file = self.drive_service.files().create(
                        body=file_metadata,
                        media_body=media,
                        fields='id,name'
                    ).execute()
                    
                    progress_queue.put({'type': 'success', 'text': f"Uploaded PDF: {clean_filename}"})
                    processed_count = 1
                else:
                    progress_queue.put({'type': 'info', 'text': f"PDF already exists, skipping: {clean_filename}"})
                
            except Exception as e:
                progress_queue.put({'type': 'error', 'text': f"Failed to process attachment {filename}: {str(e)}"})
        
        return processed_count
    
    def _clean_folder_name(self, name: str) -> str:
        """Clean folder name to be valid for Google Drive"""
        import re
        # Remove email parts and clean up
        if '@' in name:
            name = name.split('@')[0]
        # Replace invalid characters
        cleaned = re.sub(r'[<>:"/\\|?*]', '_', name)
        cleaned = re.sub(r'[^\w\s-]', '_', cleaned)
        return cleaned.strip()[:50]  # Limit length
    
    def _sanitize_filename(self, filename: str) -> str:
        """Clean up filenames to be safe for all operating systems"""
        import re
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
    
    def _file_exists_in_folder(self, filename: str, folder_id: str) -> bool:
        """Check if file already exists in folder"""
        try:
            # Check for files with same base name (excluding timestamp prefix)
            base_name = filename
            if '_' in filename:
                parts = filename.split('_')
                if len(parts) > 1:
                    base_name = '_'.join(parts[1:])  # Remove timestamp prefix
            
            query = f"name contains '{base_name}' and '{folder_id}' in parents and trashed=false"
            existing = self.drive_service.files().list(q=query, fields='files(id, name)').execute()
            files = existing.get('files', [])
            return len(files) > 0
        except:
            return False
    
    def process_pdf_workflow(self, config: dict, progress_queue: queue.Queue):
        """Process PDF workflow with LlamaParse using More Retail JSON structure"""
        try:
            if not self._check_memory(progress_queue):
                progress_queue.put({'type': 'done', 'result': {'success': False, 'processed': 0}})
                return
            
            if not LLAMA_AVAILABLE:
                progress_queue.put({'type': 'error', 'text': "LlamaParse not available. Install with: pip install llama-cloud-services"})
                progress_queue.put({'type': 'done', 'result': {'success': False, 'processed': 0}})
                return
            
            progress_queue.put({'type': 'status', 'text': "Starting PDF processing workflow..."})
            progress_queue.put({'type': 'progress', 'value': 20})
            
            # Reset statistics
            self.stats = {
                'rows_appended': 0,
                'duplicates_found': 0,
                'files_processed': 0,
                'files_failed': 0
            }
            
            # Setup LlamaParse
            os.environ["LLAMA_CLOUD_API_KEY"] = config['llama_api_key']
            extractor = LlamaExtract()
            agent = extractor.get_agent(name=config['llama_agent'])
            
            if agent is None:
                progress_queue.put({'type': 'error', 'text': f"Could not find agent '{config['llama_agent']}'. Check LlamaParse dashboard."})
                progress_queue.put({'type': 'done', 'result': {'success': False, 'processed': 0}})
                return
            
            progress_queue.put({'type': 'progress', 'value': 40})
            
            # List PDF files from Drive
            pdf_files = self._list_drive_files(config['drive_folder_id'], config['days_back'], progress_queue)
            
            if not pdf_files:
                progress_queue.put({'type': 'warning', 'text': "No PDF files found in the specified folder"})
                progress_queue.put({'type': 'done', 'result': {'success': True, 'processed': 0}})
                return
            
            progress_queue.put({'type': 'status', 'text': f"Found {len(pdf_files)} PDF files. Processing..."})
            progress_queue.put({'type': 'info', 'text': f"Processing {len(pdf_files)} PDF files from Drive folder"})
            
            # Get sheet info
            sheet_name = config['sheet_range'].split('!')[0] if '!' in config['sheet_range'] else config['sheet_range']
            
            for i, file in enumerate(pdf_files):
                if file['id'] in self.processed_pdfs:
                    progress_queue.put({'type': 'info', 'text': f"Skipping already processed PDF: {file['name']}"})
                    continue
                
                try:
                    progress_queue.put({'type': 'status', 'text': f"Processing PDF {i+1}/{len(pdf_files)}: {file['name']}"})
                    
                    # Download PDF
                    pdf_data = self._download_from_drive(file['id'], file['name'], progress_queue)
                    if not pdf_data:
                        self.stats['files_failed'] += 1
                        continue
                    
                    # Process with LlamaParse
                    with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as temp_file:
                        temp_file.write(pdf_data)
                        temp_path = temp_file.name
                    
                    progress_queue.put({'type': 'info', 'text': f"Extracting data from PDF: {file['name']}"})
                    result = agent.extract(temp_path)
                    extracted_data = result.data
                    os.unlink(temp_path)
                    
                    # Process extracted data using More Retail JSON structure
                    rows = self._process_more_retail_extracted_data(extracted_data, file, progress_queue)
                    if rows:
                        # Append each row one by one to Google Sheets
                        for row_data in rows:
                            self._append_single_row_to_sheets(
                                config['spreadsheet_id'], 
                                sheet_name, 
                                row_data, 
                                progress_queue
                            )
                        
                        self.stats['files_processed'] += 1
                        self.processed_pdfs.add(file['id'])
                        self._save_processed_state()
                        progress_queue.put({'type': 'success', 'text': f"Successfully processed {file['name']} - {len(rows)} rows added"})
                    else:
                        self.stats['files_failed'] += 1
                        progress_queue.put({'type': 'warning', 'text': f"No data extracted from {file['name']}"})
                    
                    progress = 40 + (i + 1) / len(pdf_files) * 55
                    progress_queue.put({'type': 'progress', 'value': int(progress)})
                    
                except Exception as e:
                    progress_queue.put({'type': 'error', 'text': f"Failed to process PDF {file['name']}: {str(e)}"})
                    self.stats['files_failed'] += 1
            
            progress_queue.put({'type': 'progress', 'value': 100})
            
            # Final statistics
            progress_queue.put({'type': 'stats', 'stats': self.stats.copy()})
            progress_queue.put({'type': 'status', 'text': f"PDF workflow completed!"})
            progress_queue.put({'type': 'success', 'text': f"Processed: {self.stats['files_processed']} files, Appended: {self.stats['rows_appended']} rows, Duplicates: {self.stats['duplicates_found']}, Failed: {self.stats['files_failed']}"})
            progress_queue.put({'type': 'done', 'result': {'success': True, 'processed': self.stats['files_processed']}})
            
        except Exception as e:
            progress_queue.put({'type': 'error', 'text': f"PDF workflow failed: {str(e)}"})
            progress_queue.put({'type': 'done', 'result': {'success': False, 'processed': 0}})
    
    def _list_drive_files(self, folder_id: str, days_back: int, progress_queue: queue.Queue) -> List[Dict]:
        """List PDF files in Drive folder with better error handling"""
        try:
            start_datetime = datetime.utcnow() - timedelta(days=days_back)
            start_str = start_datetime.strftime('%Y-%m-%dT00:00:00Z')
            query = f"'{folder_id}' in parents and mimeType='application/pdf' and trashed=false and createdTime >= '{start_str}'"
            
            progress_queue.put({'type': 'info', 'text': f"Searching for PDFs created after {start_str}"})
            
            all_files = []
            page_token = None
            while True:
                results = self.drive_service.files().list(
                    q=query,
                    fields="nextPageToken, files(id, name, mimeType, createdTime, modifiedTime)",
                    orderBy="createdTime desc",
                    pageSize=1000,
                    pageToken=page_token
                ).execute()
                
                files = results.get('files', [])
                all_files.extend(files)
                
                page_token = results.get('nextPageToken', None)
                if page_token is None:
                    break
            
            progress_queue.put({'type': 'info', 'text': f"Found {len(all_files)} PDF files in Drive folder"})
            return all_files
        except Exception as e:
            progress_queue.put({'type': 'error', 'text': f"Failed to list files: {str(e)}"})
            return []
    
    def _download_from_drive(self, file_id: str, file_name: str, progress_queue: queue.Queue) -> bytes:
            """Download file from Drive with better error handling"""
            try:
                request = self.drive_service.files().get_media(fileId=file_id)
                file_io = io.BytesIO()
                downloader = MediaIoBaseDownload(file_io, request)
                done = False
                while done is False:
                    status, done = downloader.next_chunk()
                
                file_io.seek(0)
                return file_io.read()
            except Exception as e:
                progress_queue.put({'type': 'error', 'text': f"Failed to download {file_name}: {str(e)}"})
                return b''
    
    def _process_more_retail_extracted_data(self, data: str, file_info: Dict, progress_queue: queue.Queue) -> List[List]:
        """Process extracted data using More Retail JSON structure"""
        try:
            import json
            
            # Try to parse as JSON
            if isinstance(data, str):
                try:
                    json_data = json.loads(data)
                except json.JSONDecodeError:
                    # If not valid JSON, try to extract JSON from text
                    import re
                    json_match = re.search(r'\{.*\}', data, re.DOTALL)
                    if json_match:
                        json_data = json.loads(json_match.group())
                    else:
                        progress_queue.put({'type': 'warning', 'text': f"No valid JSON found in extracted data from {file_info['name']}"})
                        return []
            else:
                json_data = data
            
            rows = []
            
            # More Retail specific structure - adapt based on your JSON schema
            if isinstance(json_data, dict):
                if 'items' in json_data:
                    # Process items array
                    for item in json_data['items']:
                        row = self._format_more_retail_row(item, file_info)
                        if row:
                            rows.append(row)
                elif 'products' in json_data:
                    # Process products array
                    for product in json_data['products']:
                        row = self._format_more_retail_row(product, file_info)
                        if row:
                            rows.append(row)
                else:
                    # Single item
                    row = self._format_more_retail_row(json_data, file_info)
                    if row:
                        rows.append(row)
            elif isinstance(json_data, list):
                # Array of items
                for item in json_data:
                    row = self._format_more_retail_row(item, file_info)
                    if row:
                        rows.append(row)
            
            return rows
            
        except Exception as e:
            progress_queue.put({'type': 'error', 'text': f"Failed to process extracted data from {file_info['name']}: {str(e)}"})
            return []
    
    def _format_more_retail_row(self, item: Dict, file_info: Dict) -> List:
        """Format a single item into a row for More Retail spreadsheet"""
        try:
            # Adapt these fields based on your specific More Retail data structure
            row = [
                datetime.now().strftime('%Y-%m-%d %H:%M:%S'),  # Timestamp
                file_info.get('name', ''),  # Source file
                item.get('product_name', ''),
                item.get('sku', ''),
                item.get('brand', ''),
                item.get('category', ''),
                item.get('price', ''),
                item.get('quantity', ''),
                item.get('description', ''),
                item.get('supplier', ''),
                item.get('warehouse', ''),
                item.get('status', ''),
                # Add more fields as needed for More Retail
            ]
            return row
        except Exception as e:
            return []
    
    def _append_single_row_to_sheets(self, spreadsheet_id: str, sheet_name: str, row_data: List, progress_queue: queue.Queue):
        """Append a single row to Google Sheets with duplicate checking"""
        try:
            # Check for duplicates based on key fields (adjust as needed)
            if self._is_duplicate_row(spreadsheet_id, sheet_name, row_data, progress_queue):
                self.stats['duplicates_found'] += 1
                progress_queue.put({'type': 'info', 'text': f"Duplicate found, skipping row"})
                return
            
            # Append the row
            range_name = f"{sheet_name}!A:Z"  # Adjust range as needed
            value_input_option = 'USER_ENTERED'
            
            body = {
                'values': [row_data]
            }
            
            result = self.sheets_service.spreadsheets().values().append(
                spreadsheetId=spreadsheet_id,
                range=range_name,
                valueInputOption=value_input_option,
                body=body
            ).execute()
            
            self.stats['rows_appended'] += 1
            
        except Exception as e:
            progress_queue.put({'type': 'error', 'text': f"Failed to append row to sheets: {str(e)}"})
    
    def _is_duplicate_row(self, spreadsheet_id: str, sheet_name: str, row_data: List, progress_queue: queue.Queue) -> bool:
        """Check if row already exists (basic duplicate detection)"""
        try:
            # Get existing data to check for duplicates
            range_name = f"{sheet_name}!A:Z"
            result = self.sheets_service.spreadsheets().values().get(
                spreadsheetId=spreadsheet_id,
                range=range_name
            ).execute()
            
            values = result.get('values', [])
            
            # Check if current row matches any existing row (adjust logic as needed)
            for existing_row in values:
                if len(existing_row) >= 3 and len(row_data) >= 3:
                    # Compare key fields (adjust indices based on your data structure)
                    if (existing_row[2] == row_data[2] and  # product_name
                        existing_row[3] == row_data[3]):     # sku
                        return True
            
            return False
            
        except Exception as e:
            # If we can't check, assume it's not a duplicate
            return False

# Streamlit UI
def main():
    st.title("🛒 More Retail AWS Automation")
    st.markdown("Automate Gmail attachment downloads and PDF processing workflows")
    
    # Initialize automation
    if 'automation' not in st.session_state:
        st.session_state.automation = MoreRetailAutomation()
    
    automation = st.session_state.automation
    
    # Sidebar configuration
    st.sidebar.header("Configuration")
    
    # Authentication status
    if automation.authentication_complete:
        st.sidebar.success("✅ Authenticated with Google APIs")
    else:
        st.sidebar.warning("⚠️ Authentication required")
        if st.sidebar.button("Authenticate Now"):
            st.rerun()
    
    # Workflow selection
    workflow = st.sidebar.selectbox(
        "Select Workflow",
        ["Gmail Attachment Downloader", "PDF Processor", "Both Workflows"]
    )
    
    # Configuration tabs
    tab1, tab2 = st.tabs(["Gmail Config", "PDF Config"])
    
    with tab1:
        st.subheader("Gmail Attachment Configuration")
        
        gmail_config = {
            'sender': st.text_input("Sender Email (optional)", placeholder="supplier@example.com"),
            'search_term': st.text_input("Search Keywords", placeholder="invoice, receipt, report"),
            'days_back': st.slider("Days to search back", 1, 30, 7),
            'max_results': st.slider("Max emails to process", 10, 200, 50),
            'gdrive_folder_id': st.text_input("Google Drive Folder ID (optional)", placeholder="1ABC...")
        }
    
    with tab2:
        st.subheader("PDF Processing Configuration")
        
        pdf_config = {
            'llama_api_key': st.text_input("LlamaParse API Key", type="password"),
            'llama_agent': st.text_input("LlamaParse Agent Name", value="more_retail_extractor"),
            'drive_folder_id': st.text_input("Drive Folder ID for PDFs", placeholder="1ABC..."),
            'spreadsheet_id': st.text_input("Google Sheets ID", placeholder="1ABC..."),
            'sheet_range': st.text_input("Sheet Range", value="Sheet1"),
            'days_back': st.slider("Days back for PDFs", 1, 30, 7)
        }
    
    # Action buttons
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("🔄 Run Gmail Workflow", disabled=not automation.authentication_complete):
            run_workflow("gmail", gmail_config, automation)
    
    with col2:
        if st.button("📄 Run PDF Workflow", disabled=not automation.authentication_complete):
            run_workflow("pdf", pdf_config, automation)
    
    with col3:
        if st.button("🚀 Run Both Workflows", disabled=not automation.authentication_complete):
            run_workflow("both", {**gmail_config, **pdf_config}, automation)
    
    # Auto-refresh for real-time updates
    st_autorefresh(interval=2000, key="datarefresh")
    
    # Display results
    if 'workflow_results' in st.session_state:
        st.subheader("Workflow Results")
        results = st.session_state.workflow_results
        
        if results.get('messages'):
            for msg in results['messages'][-10:]:  # Show last 10 messages
                if msg['type'] == 'success':
                    st.success(msg['text'])
                elif msg['type'] == 'error':
                    st.error(msg['text'])
                elif msg['type'] == 'warning':
                    st.warning(msg['text'])
                else:
                    st.info(msg['text'])
        
        # Statistics
        if results.get('stats'):
            st.subheader("Processing Statistics")
            stats = results['stats']
            
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Files Processed", stats.get('files_processed', 0))
            with col2:
                st.metric("Rows Added", stats.get('rows_appended', 0))
            with col3:
                st.metric("Duplicates Found", stats.get('duplicates_found', 0))
            with col4:
                st.metric("Failed Files", stats.get('files_failed', 0))

def run_workflow(workflow_type: str, config: dict, automation: MoreRetailAutomation):
    """Run the selected workflow with real-time updates"""
    
    # Initialize session state for results
    if 'workflow_results' not in st.session_state:
        st.session_state.workflow_results = {'messages': [], 'stats': {}}
    
    # Clear previous results
    st.session_state.workflow_results = {'messages': [], 'stats': {}}
    
    # Authentication check
    if not automation.authentication_complete:
        progress_container = st.container()
        with progress_container:
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            # Create progress queue for authentication
            progress_queue = queue.Queue()
            
            # Authenticate
            success = automation.authenticate_from_secrets(progress_bar, status_text, progress_queue)
            
            # Process authentication messages
            while not progress_queue.empty():
                try:
                    msg = progress_queue.get_nowait()
                    st.session_state.workflow_results['messages'].append(msg)
                except queue.Empty:
                    break
            
            if not success:
                st.error("Authentication failed. Please check your credentials.")
                return
    
    # Run workflow in thread
    progress_container = st.container()
    with progress_container:
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        # Create progress queue
        progress_queue = queue.Queue()
        
        # Start workflow thread
        if workflow_type == "gmail":
            thread = threading.Thread(target=automation.process_gmail_workflow, args=(config, progress_queue))
        elif workflow_type == "pdf":
            thread = threading.Thread(target=automation.process_pdf_workflow, args=(config, progress_queue))
        elif workflow_type == "both":
            # Run both workflows sequentially
            thread = threading.Thread(target=run_both_workflows, args=(automation, config, progress_queue))
        
        thread.start()
        
        # Update UI with real-time progress
        while thread.is_alive() or not progress_queue.empty():
            try:
                msg = progress_queue.get(timeout=1)
                
                if msg['type'] == 'progress':
                    progress_bar.progress(msg['value'])
                elif msg['type'] == 'status':
                    status_text.text(msg['text'])
                elif msg['type'] == 'stats':
                    st.session_state.workflow_results['stats'] = msg['stats']
                elif msg['type'] == 'done':
                    break
                else:
                    st.session_state.workflow_results['messages'].append(msg)
                
            except queue.Empty:
                continue
        
        thread.join()
        
        # Process remaining messages
        while not progress_queue.empty():
            try:
                msg = progress_queue.get_nowait()
                if msg['type'] == 'stats':
                    st.session_state.workflow_results['stats'] = msg['stats']
                else:
                    st.session_state.workflow_results['messages'].append(msg)
            except queue.Empty:
                break

def run_both_workflows(automation: MoreRetailAutomation, config: dict, progress_queue: queue.Queue):
    """Run both Gmail and PDF workflows sequentially"""
    try:
        progress_queue.put({'type': 'status', 'text': "Starting combined workflow..."})
        
        # Run Gmail workflow first
        progress_queue.put({'type': 'info', 'text': "Phase 1: Gmail attachment download"})
        automation.process_gmail_workflow(config, progress_queue)
        
        # Small delay between workflows
        time.sleep(2)
        
        # Run PDF workflow
        progress_queue.put({'type': 'info', 'text': "Phase 2: PDF processing"})
        automation.process_pdf_workflow(config, progress_queue)
        
        progress_queue.put({'type': 'status', 'text': "Combined workflow completed!"})
        progress_queue.put({'type': 'done', 'result': {'success': True, 'processed': 0}})
        
    except Exception as e:
        progress_queue.put({'type': 'error', 'text': f"Combined workflow failed: {str(e)}"})
        progress_queue.put({'type': 'done', 'result': {'success': False, 'processed': 0}})

if __name__ == "__main__":
    main()
