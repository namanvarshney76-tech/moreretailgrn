#!/usr/bin/env python3
"""
Streamlit App for More Retail AWS Automation Workflows
Combines Gmail attachment downloader and PDF processor with real-time tracking
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
        process = psutil.Process()
        mem_info = process.memory_info()
        if mem_info.rss > 0.8 * psutil.virtual_memory().total:  # 80% of total memory
            progress_queue.put({'type': 'error', 'text': "Memory usage too high, stopping to prevent crash"})
            return False
        return True
    
    def authenticate_from_secrets(self, progress_queue: queue.Queue):
        """Authenticate using Streamlit secrets with web-based OAuth flow"""
        try:
            progress_queue.put({'type': 'status', 'text': "Starting authentication..."})
            progress_queue.put({'type': 'progress', 'value': 10})
            
            # Check for existing token in session state
            if 'oauth_token' in st.session_state:
                try:
                    combined_scopes = list(set(self.gmail_scopes + self.drive_scopes + self.sheets_scopes))
                    creds = Credentials.from_authorized_user_info(st.session_state.oauth_token, combined_scopes)
                    if creds and creds.valid:
                        progress_queue.put({'type': 'progress', 'value': 50})
                        # Build services
                        self.gmail_service = build('gmail', 'v1', credentials=creds)
                        self.drive_service = build('drive', 'v3', credentials=creds)
                        self.sheets_service = build('sheets', 'v4', credentials=creds)
                        progress_queue.put({'type': 'progress', 'value': 100})
                        progress_queue.put({'type': 'success', 'text': "Authentication successful!"})
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
                        
                        progress_queue.put({'type': 'progress', 'value': 50})
                        # Build services
                        self.gmail_service = build('gmail', 'v1', credentials=creds)
                        self.drive_service = build('drive', 'v3', credentials=creds)
                        self.sheets_service = build('sheets', 'v4', credentials=creds)
                        
                        progress_queue.put({'type': 'progress', 'value': 100})
                        progress_queue.put({'type': 'success', 'text': "Authentication successful!"})
                        self.authentication_complete = True
                        
                        # Clear the code from URL
                        st.query_params.clear()
                        return True
                    except Exception as e:
                        progress_queue.put({'type': 'error', 'text': f"Authentication failed: {str(e)}"})
                        return False
                else:
                    # Show authorization link
                    progress_queue.put({'type': 'auth_required', 'auth_url': auth_url})
                    return False
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
            progress_queue.put({'type': 'info', 'text': f"Searching Gmail with query: {query}"})
            
            # Execute search
            result = self.gmail_service.users().messages().list(
                userId='me', q=query, maxResults=max_results
            ).execute()
            
            messages = result.get('messages', [])
            progress_queue.put({'type': 'info', 'text': f"Gmail search returned {len(messages)} messages"})
            
            return messages
            
        except Exception as e:
            progress_queue.put({'type': 'error', 'text': f"Email search failed: {str(e)}"})
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
            progress_queue.put({'type': 'info', 'text': f"Found {len(emails)} emails matching criteria"})
            
            # Create base folder in Drive
            base_folder_name = "More_Retail_Attachments"
            base_folder_id = self._create_drive_folder(base_folder_name, config.get('gdrive_folder_id'), progress_queue)
            
            if not base_folder_id:
                progress_queue.put({'type': 'error', 'text': "Failed to create base folder in Google Drive"})
                progress_queue.put({'type': 'done', 'result': {'success': False, 'processed': 0}})
                return
            
            progress_queue.put({'type': 'progress', 'value': 50})
            
            processed_count = 0
            total_attachments = 0
            
            for i, email in enumerate(emails):
                if email['id'] in self.processed_emails:
                    progress_queue.put({'type': 'info', 'text': f"Skipping already processed email ID: {email['id']}"})
                    continue
                
                try:
                    progress_queue.put({'type': 'status', 'text': f"Processing email {i+1}/{len(emails)}"})
                    
                    # Get email details
                    email_details = self._get_email_details(email['id'], progress_queue)
                    subject = email_details.get('subject', 'No Subject')[:50]
                    sender = email_details.get('sender', 'Unknown')
                    
                    progress_queue.put({'type': 'info', 'text': f"Processing email: {subject} from {sender}"})
                    
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
                        progress_queue.put({'type': 'success', 'text': f"Found {attachment_count} attachments in: {subject}"})
                    else:
                        progress_queue.put({'type': 'info', 'text': f"No matching attachments in: {subject}"})
                    
                    progress = 50 + (i + 1) / len(emails) * 45
                    progress_queue.put({'type': 'progress', 'value': int(progress)})
                    
                except Exception as e:
                    progress_queue.put({'type': 'error', 'text': f"Failed to process email {email.get('id', 'unknown')}: {str(e)}"})
            
            progress_queue.put({'type': 'progress', 'value': 100})
            progress_queue.put({'type': 'status', 'text': f"Gmail workflow completed! Processed {total_attachments} attachments from {processed_count} emails"})
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
            progress_queue.put({'type': 'error', 'text': f"Failed to get email details for {message_id}: {str(e)}"})
            return {'id': message_id, 'sender': 'Unknown', 'subject': 'Unknown', 'date': ''}
    
    def _create_drive_folder(self, folder_name: str, parent_folder_id: Optional[str] = None, progress_queue: queue.Queue = None) -> str:
        """Create a folder in Google Drive"""
        try:
            # Check if folder already exists
            query = f"name='{folder_name}' and mimeType='application/vnd.google-apps.folder' and trashed=false"
            if parent_folder_id:
                query += f" and '{parent_folder_id}' in parents"
            
            existing = self.drive_service.files().list(q=query, fields='files(id, name)').execute()
            files = existing.get('files', [])
            
            if files:
                return files[0]['id']
            
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
            
            return folder.get('id')
            
        except Exception as e:
            progress_queue.put({'type': 'error', 'text': f"Failed to create folder {folder_name}: {str(e)}"})
            return ""
    
    def _extract_attachments_from_email(self, message_id: str, payload: Dict, config: dict, base_folder_id: str, progress_queue: queue.Queue) -> int:
        """Extract attachments from email with proper folder structure"""
        processed_count = 0
        
        if "parts" in payload:
            for part in payload["parts"]:
                processed_count += self._extract_attachments_from_email(
                    message_id, part, config, base_folder_id, progress_queue
                )
        elif payload.get("filename") and "attachmentId" in payload.get("body", {}):
            filename = payload.get("filename", "")
            
            try:
                # Get attachment data
                attachment_id = payload["body"].get("attachmentId")
                att = self.gmail_service.users().messages().attachments().get(
                    userId='me', messageId=message_id, id=attachment_id
                ).execute()
                
                file_data = base64.urlsafe_b64decode(att["data"].encode("UTF-8"))
                
                # Create nested folder structure
                search_term = config.get('search_term', 'all-attachments')
                search_folder_name = search_term if search_term else "all-attachments"
                file_type_folder = self._classify_extension(filename)
                
                # Create search term folder
                search_folder_id = self._create_drive_folder(search_folder_name, base_folder_id, progress_queue)
                
                # Create file type folder within search folder
                type_folder_id = self._create_drive_folder(file_type_folder, search_folder_id, progress_queue)
                
                # Clean filename
                clean_filename = self._sanitize_filename(filename)
                final_filename = clean_filename
                
                # Check if file already exists
                if not self._file_exists_in_folder(final_filename, type_folder_id):
                    # Upload to Drive
                    file_metadata = {
                        'name': final_filename,
                        'parents': [type_folder_id]
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
                    
                    progress_queue.put({'type': 'info', 'text': f"Uploaded: {final_filename}"})
                    processed_count = 1
                else:
                    progress_queue.put({'type': 'info', 'text': f"File already exists, skipping: {final_filename}"})
                
            except Exception as e:
                progress_queue.put({'type': 'error', 'text': f"Failed to process attachment {filename}: {str(e)}"})
        
        return processed_count
    
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
    
    def _file_exists_in_folder(self, filename: str, folder_id: str) -> bool:
        """Check if file already exists in folder"""
        try:
            query = f"name='{filename}' and '{folder_id}' in parents and trashed=false"
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
                    else:
                        self.stats['files_failed'] += 1
                    
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
        """List PDF files in Drive folder"""
        try:
            start_datetime = datetime.utcnow() - timedelta(days=days_back - 1)
            start_str = start_datetime.strftime('%Y-%m-%dT00:00:00Z')
            query = f"'{folder_id}' in parents and mimeType='application/pdf' and trashed=false and createdTime >= '{start_str}'"
            
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
            
            return all_files
        except Exception as e:
            progress_queue.put({'type': 'error', 'text': f"Failed to list files: {str(e)}"})
            return []
    
    def _download_from_drive(self, file_id: str, file_name: str, progress_queue: queue.Queue) -> bytes:
        """Download file from Drive"""
        try:
            request = self.drive_service.files().get_media(fileId=file_id)
            return request.execute()
        except Exception as e:
            progress_queue.put({'type': 'error', 'text': f"Failed to download {file_name}: {str(e)}"})
            return b""
    
    def _process_more_retail_extracted_data(self, extracted_data: Dict, file_info: Dict, progress_queue: queue.Queue) -> List[Dict]:
        """Process extracted data using More Retail JSON structure"""
        rows = []
        
        try:
            # Extract common fields from the JSON structure
            company_name = extracted_data.get("company_name", "")
            company_address = extracted_data.get("company_address", "")
            shipping_address = extracted_data.get("shipping_address", "")
            grn_number = extracted_data.get("grn_number", "")
            grn_date = extracted_data.get("grn_date", "")
            po_number = extracted_data.get("po_number", "")
            vendor_invoice_no = extracted_data.get("vendor_invoice_no", "")
            gstin_company = extracted_data.get("gstin_company", "")
            shipment_number = extracted_data.get("shipment_number", "")
            
            # Process items if they exist
            items = extracted_data.get("items", [])
            
            if not items:
                progress_queue.put({'type': 'warning', 'text': f"No items found in PDF: {file_info['name']}"})
                return rows
            
            for item in items:
                row_data = {
                    # Common fields for all items
                    "company_name": company_name,
                    "company_address": company_address,
                    "shipping_address": shipping_address,
                    "grn_number": grn_number,
                    "grn_date": grn_date,
                    "po_number": po_number,
                    "vendor_invoice_no": vendor_invoice_no,
                    "gstin_company": gstin_company,
                    "shipment_number": shipment_number,
                    
                    # Item-specific fields
                    "sku": item.get("sku", ""),
                    "item_description": item.get("item_description", ""),
                    "hsn_code": item.get("hsn_code", ""),
                    "variant_ean_code": item.get("variant_ean_code", ""),
                    "mrp_inr": item.get("mrp_inr", ""),
                    "cp": item.get("cp", ""),
                    "uom": item.get("uom", ""),
                    "qty": item.get("qty", ""),
                    "tax_percentage": item.get("tax_percentage", ""),
                    "tax_amt_inr": item.get("tax_amt_inr", ""),
                    "value_inr": item.get("value_inr", ""),
                    
                    # Metadata
                    "source_file": file_info['name'],
                    "processed_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "drive_file_id": file_info['id']
                }
                
                # Clean the row data (remove empty values)
                cleaned_row = {k: v for k, v in row_data.items() if v not in ["", None]}
                rows.append(cleaned_row)
                
            progress_queue.put({'type': 'info', 'text': f"Extracted {len(rows)} items from {file_info['name']}"})
            
        except Exception as e:
            progress_queue.put({'type': 'error', 'text': f"Failed to process extracted data from {file_info['name']}: {str(e)}"})
            
        return rows
    
    def _append_single_row_to_sheets(self, spreadsheet_id: str, sheet_name: str, row_data: Dict, progress_queue: queue.Queue):
        """Append a single row to Google Sheets with duplicate checking"""
        try:
            # Get existing headers
            headers = self._get_or_create_sheet_headers(spreadsheet_id, sheet_name, row_data.keys(), progress_queue)
            
            # Check for duplicates based on grn_number and sku
            is_duplicate = self._check_for_duplicate(spreadsheet_id, sheet_name, row_data, progress_queue)
            
            if is_duplicate:
                self.stats['duplicates_found'] += 1
                progress_queue.put({'type': 'warning', 'text': f"Duplicate found for GRN: {row_data.get('grn_number', 'N/A')}, SKU: {row_data.get('sku', 'N/A')}"})
                return
            
            # Prepare row values in the order of headers
            row_values = [row_data.get(header, "") for header in headers]
            
            # Append to sheet
            body = {'values': [row_values]}
            result = self.sheets_service.spreadsheets().values().append(
                spreadsheetId=spreadsheet_id,
                range=sheet_name,
                valueInputOption='USER_ENTERED',
                body=body
            ).execute()
            
            self.stats['rows_appended'] += 1
            progress_queue.put({'type': 'info', 'text': f"Appended row for GRN: {row_data.get('grn_number', 'N/A')}, SKU: {row_data.get('sku', 'N/A')}"})
            
        except Exception as e:
            progress_queue.put({'type': 'error', 'text': f"Failed to append row to sheet: {str(e)}"})
    
    def _get_or_create_sheet_headers(self, spreadsheet_id: str, sheet_name: str, new_fields: List[str], progress_queue: queue.Queue) -> List[str]:
        """Get existing headers or create new ones"""
        try:
            # Try to get existing headers
            result = self.sheets_service.spreadsheets().values().get(
                spreadsheetId=spreadsheet_id,
                range=f"{sheet_name}!A1:Z1"
            ).execute()
            
            existing_headers = result.get('values', [[]])[0] if result.get('values') else []
            
            # If no headers exist, create them
            if not existing_headers:
                headers = list(new_fields)
                body = {'values': [headers]}
                self.sheets_service.spreadsheets().values().update(
                    spreadsheetId=spreadsheet_id,
                    range=f"{sheet_name}!A1:{chr(64 + len(headers))}1",
                    valueInputOption='USER_ENTERED',
                    body=body
                ).execute()
                progress_queue.put({'type': 'info', 'text': f"Created headers for sheet: {sheet_name}"})
                return headers
            
            # Check if we need to add new headers
            headers_to_add = [field for field in new_fields if field not in existing_headers]
            
            if headers_to_add:
                updated_headers = existing_headers + headers_to_add
                body = {'values': [updated_headers]}
                self.sheets_service.spreadsheets().values().update(
                    spreadsheetId=spreadsheet_id,
                    range=f"{sheet_name}!A1:{chr(64 + len(updated_headers))}1",
                    valueInputOption='USER_ENTERED',
                    body=body
                ).execute()
                progress_queue.put({'type': 'info', 'text': f"Added {len(headers_to_add)} new headers to sheet"})
                return updated_headers
            
            return existing_headers
            
        except Exception as e:
            progress_queue.put({'type': 'error', 'text': f"Failed to manage headers: {str(e)}"})
            return list(new_fields)
    
    def _check_for_duplicate(self, spreadsheet_id: str, sheet_name: str, row_data: Dict, progress_queue: queue.Queue) -> bool:
        """Check if a row with the same GRN number and SKU already exists"""
        try:
            grn_number = row_data.get('grn_number', '')
            sku = row_data.get('sku', '')
            
            if not grn_number or not sku:
                return False
            
            # Get all data from sheet
            result = self.sheets_service.spreadsheets().values().get(
                spreadsheetId=spreadsheet_id,
                range=sheet_name
            ).execute()
            
            values = result.get('values', [])
            if len(values) <= 1:  # Only headers or empty sheet
                return False
            
            headers = values[0]
            data_rows = values[1:]
            
            # Find column indices
            try:
                grn_col = headers.index('grn_number')
                sku_col = headers.index('sku')
            except ValueError:
                return False  # Columns don't exist yet
            
            # Check for duplicates
            for row in data_rows:
                if (len(row) > grn_col and len(row) > sku_col and 
                    row[grn_col] == grn_number and row[sku_col] == sku):
                    return True
            
            return False
            
        except Exception as e:
            progress_queue.put({'type': 'error', 'text': f"Failed to check for duplicates: {str(e)}"})
            return False

def run_workflow_in_background(automation, workflow_type, gmail_config, pdf_config, progress_queue):
    """Run the selected workflow in background, sending updates to queue"""
    try:
        if workflow_type == "gmail":
            automation.process_gmail_workflow(gmail_config, progress_queue)
        elif workflow_type == "pdf":
            automation.process_pdf_workflow(pdf_config, progress_queue)
        elif workflow_type == "combined":
            progress_queue.put({'type': 'info', 'text': "Running combined workflow..."})
            progress_queue.put({'type': 'status', 'text': "Step 1: Gmail Attachment Download"})
            automation.process_gmail_workflow(gmail_config, progress_queue)
            time.sleep(2)  # Small delay between steps
            progress_queue.put({'type': 'status', 'text': "Step 2: PDF Processing"})
            automation.process_pdf_workflow(pdf_config, progress_queue)
            progress_queue.put({'type': 'success', 'text': "Combined workflow completed successfully!"})
    except Exception as e:
        progress_queue.put({'type': 'error', 'text': f"Workflow execution failed: {str(e)}"})
        progress_queue.put({'type': 'done', 'result': {'success': False, 'processed': 0}})

def main():
    st.title("🛒 More Retail AWS Automation Dashboard")
    st.markdown("Automate Gmail attachment downloads and PDF processing workflows for More Retail")
    
    # Initialize session state for configuration
    if 'gmail_config' not in st.session_state:
        st.session_state.gmail_config = {
            'sender': "aws-reports@moreretail.in",
            'search_term': "in:spam ",
            'days_back': 7,
            'max_results': 1000,
            'gdrive_folder_id': "1gZoNjdGarwMD5-Ci3uoqjNZZ8bTNyVoy"
        }
    
    if 'pdf_config' not in st.session_state:
        st.session_state.pdf_config = {
            'drive_folder_id': "1XHIFX-Gsb_Mx_AYjoi2NG1vMlvNE5CmQ",
            'llama_api_key': "llx-4ob5GL9KL1Dyl3y59FhByo2tLlb4kQZkSDLEOYh4SR9YZ9uZ",
            'llama_agent': "More retail Agent",
            'spreadsheet_id': "16y9DAK2tVHgnZNnPeRoSSPPE2NcspW_qqMF8ZR8OOC0",
            'sheet_range': "mraws",
            'days_back': 1
        }
    
    # Initialize workflow state
    if 'workflow_state' not in st.session_state:
        st.session_state.workflow_state = {
            'running': False,
            'type': None,
            'progress': 0,
            'status': '',
            'logs': [],
            'result': None,
            'thread': None,
            'queue': queue.Queue(),
            'authenticated': False,
            'stats': None
        }
    
    # Initialize automation instance
    if 'automation' not in st.session_state:
        st.session_state.automation = MoreRetailAutomation()
    
    # Create tabs
    tab1, tab2, tab3 = st.tabs(["Configuration", "Workflows", "Logs"])
    
    with tab1:
        st.header("Configuration Settings")
        
        # Authentication Section
        st.subheader("🔐 Authentication")
        auth_col1, auth_col2 = st.columns([2, 1])
        
        with auth_col1:
            if not st.session_state.automation.authentication_complete:
                st.warning("⚠️ Authentication required before running workflows")
                auth_progress = st.progress(0)
                auth_status = st.empty()
                
                if st.button("🔑 Authenticate with Google", type="primary"):
                    # Start authentication
                    auth_thread = threading.Thread(
                        target=st.session_state.automation.authenticate_from_secrets,
                        args=(st.session_state.workflow_state['queue'],)
                    )
                    auth_thread.start()
                    
                    # Wait for auth result
                    while auth_thread.is_alive():
                        time.sleep(0.1)
                        st.rerun()
                    
                    # Check for auth messages
                    while not st.session_state.workflow_state['queue'].empty():
                        msg = st.session_state.workflow_state['queue'].get()
                        if msg['type'] == 'progress':
                            auth_progress.progress(msg['value'])
                        elif msg['type'] == 'status':
                            auth_status.text(msg['text'])
                        elif msg['type'] == 'success':
                            st.success("✅ Authentication successful!")
                            st.session_state.workflow_state['authenticated'] = True
                            time.sleep(1)
                            st.rerun()
                        elif msg['type'] == 'auth_required':
                            st.markdown("### Google Authentication Required")
                            st.markdown(f"[🔗 Authorize with Google]({msg['auth_url']})")
                            st.info("Click the link above to authorize, you'll be redirected back automatically")
                        elif msg['type'] == 'error':
                            st.error(f"❌ {msg['text']}")
            else:
                st.success("✅ Authentication completed successfully!")
        
        # Gmail Configuration
        st.subheader("📧 Gmail Settings")
        with st.form("gmail_config_form"):
            gmail_sender = st.text_input("Sender Email", value=st.session_state.gmail_config['sender'])
            gmail_search = st.text_input("Search Terms (comma-separated)", value=st.session_state.gmail_config['search_term'])
            gmail_days = st.number_input("Days Back", value=st.session_state.gmail_config['days_back'], min_value=1)
            gmail_max = st.number_input("Max Results", value=st.session_state.gmail_config['max_results'], min_value=1)
            gmail_folder = st.text_input("Google Drive Folder ID", value=st.session_state.gmail_config['gdrive_folder_id'])
            
            gmail_submit = st.form_submit_button("💾 Update Gmail Settings")
            
            if gmail_submit:
                st.session_state.gmail_config = {
                    'sender': gmail_sender,
                    'search_term': gmail_search,
                    'days_back': gmail_days,
                    'max_results': gmail_max,
                    'gdrive_folder_id': gmail_folder
                }
                st.success("✅ Gmail settings updated!")
        
        # PDF Processing Configuration
        st.subheader("📄 PDF Processing Settings")
        with st.form("pdf_config_form"):
            pdf_folder = st.text_input("PDF Drive Folder ID", value=st.session_state.pdf_config['drive_folder_id'])
            pdf_api_key = st.text_input("LlamaParse API Key", value=st.session_state.pdf_config['llama_api_key'], type="password")
            pdf_agent = st.text_input("LlamaParse Agent Name", value=st.session_state.pdf_config['llama_agent'])
            pdf_sheet_id = st.text_input("Google Spreadsheet ID", value=st.session_state.pdf_config['spreadsheet_id'])
            pdf_sheet_range = st.text_input("Sheet Name", value=st.session_state.pdf_config['sheet_range'])
            pdf_days = st.number_input("PDF Days Back", value=st.session_state.pdf_config['days_back'], min_value=1)
            
            pdf_submit = st.form_submit_button("💾 Update PDF Settings")
            
            if pdf_submit:
                st.session_state.pdf_config = {
                    'drive_folder_id': pdf_folder,
                    'llama_api_key': pdf_api_key,
                    'llama_agent': pdf_agent,
                    'spreadsheet_id': pdf_sheet_id,
                    'sheet_range': pdf_sheet_range,
                    'days_back': pdf_days
                }
                st.success("✅ PDF settings updated!")
    
    with tab2:
        st.header("Workflow Execution")
        
        if not st.session_state.automation.authentication_complete:
            st.error("❌ Please authenticate first in the Configuration tab")
            return
        
        # Workflow Selection
        st.subheader("Choose Workflow Type")
        
        workflow_col1, workflow_col2, workflow_col3 = st.columns(3)
        
        with workflow_col1:
            st.info("📧 Gmail Workflow")
            st.write("Download and organize email attachments")
            gmail_disabled = st.session_state.workflow_state['running']
            if st.button("📥 Gmail Only", disabled=gmail_disabled, use_container_width=True):
                st.session_state.workflow_state['type'] = "gmail"
        
        with workflow_col2:
            st.info("📄 PDF Workflow")
            st.write("Extract data from PDFs to Google Sheets")
            pdf_disabled = st.session_state.workflow_state['running']
            if st.button("📊 PDF Only", disabled=pdf_disabled, use_container_width=True):
                st.session_state.workflow_state['type'] = "pdf"
        
        with workflow_col3:
            st.info("🔄 Combined Workflow")
            st.write("Gmail + PDF processing together")
            combined_disabled = st.session_state.workflow_state['running']
            if st.button("⚡ Combined", disabled=combined_disabled, use_container_width=True):
                st.session_state.workflow_state['type'] = "combined"
        
        # Start Button
        if st.session_state.workflow_state['type'] and not st.session_state.workflow_state['running']:
            st.markdown("---")
            st.subheader(f"Start {st.session_state.workflow_state['type'].title()} Workflow")
            
            if st.button(f"🚀 START {st.session_state.workflow_state['type'].upper()} WORKFLOW", 
                        type="primary", use_container_width=True):
                # Start the background thread
                thread = threading.Thread(
                    target=run_workflow_in_background,
                    args=(st.session_state.automation, st.session_state.workflow_state['type'], 
                          st.session_state.gmail_config, st.session_state.pdf_config, 
                          st.session_state.workflow_state['queue'])
                )
                thread.start()
                
                # Update workflow state
                st.session_state.workflow_state['running'] = True
                st.session_state.workflow_state['thread'] = thread
                st.session_state.workflow_state['logs'] = []
                st.session_state.workflow_state['progress'] = 0
                st.session_state.workflow_state['status'] = "Initializing..."
                st.rerun()
        
        # Running workflow status
        if st.session_state.workflow_state['running']:
            st_autorefresh(interval=1000, key="workflow_refresh")
            
            st.subheader(f"Running {st.session_state.workflow_state['type'].title()} Workflow")
            
            # Poll the queue for updates
            while not st.session_state.workflow_state['queue'].empty():
                msg = st.session_state.workflow_state['queue'].get()
                if msg['type'] == 'progress':
                    st.session_state.workflow_state['progress'] = msg['value']
                elif msg['type'] == 'status':
                    st.session_state.workflow_state['status'] = msg['text']
                elif msg['type'] in ['info', 'warning', 'error', 'success']:
                    timestamp = datetime.now().strftime("%H:%M:%S")
                    log_entry = f"[{timestamp}] {msg['type'].upper()}: {msg['text']}"
                    st.session_state.workflow_state['logs'].append(log_entry)
                elif msg['type'] == 'stats':
                    st.session_state.workflow_state['stats'] = msg['stats']
                elif msg['type'] == 'done':
                    st.session_state.workflow_state['result'] = msg['result']
                    st.session_state.workflow_state['running'] = False
            
            # Progress display
            progress_col1, progress_col2 = st.columns([3, 1])
            with progress_col1:
                st.progress(st.session_state.workflow_state['progress'] / 100)
            with progress_col2:
                st.metric("Progress", f"{st.session_state.workflow_state['progress']}%")
            
            st.text(f"Status: {st.session_state.workflow_state['status']}")
            
            # Statistics display (if available)
            if st.session_state.workflow_state['stats']:
                st.subheader("📊 Current Statistics")
                stats_col1, stats_col2, stats_col3, stats_col4 = st.columns(4)
                
                with stats_col1:
                    st.metric("Files Processed", st.session_state.workflow_state['stats']['files_processed'])
                with stats_col2:
                    st.metric("Rows Appended", st.session_state.workflow_state['stats']['rows_appended'])
                with stats_col3:
                    st.metric("Duplicates Found", st.session_state.workflow_state['stats']['duplicates_found'])
                with stats_col4:
                    st.metric("Files Failed", st.session_state.workflow_state['stats']['files_failed'])
            
            # Check if workflow is done
            if not st.session_state.workflow_state['running']:
                result = st.session_state.workflow_state['result']
                if result and result['success']:
                    st.success(f"🎉 {st.session_state.workflow_state['type'].capitalize()} workflow completed successfully!")
                    if st.session_state.workflow_state['stats']:
                        st.balloons()
                elif result:
                    st.error(f"❌ {st.session_state.workflow_state['type'].capitalize()} workflow failed")
                
                if st.button("🔄 Reset Workflow"):
                    st.session_state.workflow_state['type'] = None
                    st.session_state.workflow_state['result'] = None
                    st.session_state.workflow_state['stats'] = None
                    st.rerun()
    
    with tab3:
        st.header("📋 Workflow Logs")
        
        if st.session_state.workflow_state['logs']:
            # Filter options
            filter_col1, filter_col2 = st.columns([1, 3])
            with filter_col1:
                log_filter = st.selectbox("Filter by type:", 
                                        ["All", "INFO", "WARNING", "ERROR", "SUCCESS"])
            
            # Filter logs
            filtered_logs = st.session_state.workflow_state['logs']
            if log_filter != "All":
                filtered_logs = [log for log in st.session_state.workflow_state['logs'] 
                               if log_filter in log]
            
            # Display logs in a text area
            log_text = "\n".join(filtered_logs[-100:])  # Show last 100 logs
            st.text_area("Real-time Logs", log_text, height=400)
            
            # Download logs button
            if st.button("💾 Download Logs"):
                log_content = "\n".join(st.session_state.workflow_state['logs'])
                st.download_button(
                    label="📥 Download Log File",
                    data=log_content,
                    file_name=f"more_retail_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                    mime="text/plain"
                )
        else:
            st.info("No logs available. Start a workflow to see real-time logs here.")
        
        # Clear logs button
        if st.session_state.workflow_state['logs']:
            if st.button("🗑️ Clear Logs"):
                st.session_state.workflow_state['logs'] = []
                st.rerun()
    
    # Footer with reset options
    st.markdown("---")
    footer_col1, footer_col2 = st.columns(2)
    
    with footer_col1:
        if st.button("🔄 Reset Current Workflow", use_container_width=True):
            st.session_state.workflow_state['type'] = None
            st.session_state.workflow_state['result'] = None
            st.session_state.workflow_state['stats'] = None
            st.rerun()
    
    with footer_col2:
        if st.button("🗑️ Reset All Data", use_container_width=True, type="secondary"):
            for key in ['gmail_config', 'pdf_config', 'workflow_state', 'automation']:
                if key in st.session_state:
                    del st.session_state[key]
            if os.path.exists("more_retail_processed_state.json"):
                os.remove("more_retail_processed_state.json")
            st.rerun()

if __name__ == "__main__":
    main()
