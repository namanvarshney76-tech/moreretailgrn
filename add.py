#!/usr/bin/env python3
"""
Streamlit App for Zepto Automation Workflows
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

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from googleapiclient.http import MediaIoBaseUpload
import io

# Try to import LlamaParse
try:
    from llama_cloud_services import LlamaExtract
    LLAMA_AVAILABLE = True
except ImportError:
    LLAMA_AVAILABLE = False

# Configure Streamlit page
st.set_page_config(
    page_title="Zepto Automation",
    page_icon="⚡",
    layout="wide",
    initial_sidebar_state="expanded"
)

class StreamlitLogHandler(logging.Handler):
    """Custom log handler for Streamlit"""
    def __init__(self, log_container):
        super().__init__()
        self.log_container = log_container
        self.logs = []
    
    def emit(self, record):
        log_entry = self.format(record)
        self.logs.append(log_entry)
        # Update the container with latest logs
        with self.log_container:
            st.text_area("Real-time Logs", "\n".join(self.logs[-50:]), height=200, key=f"logs_{len(self.logs)}")

class ZeptoAutomation:
    def __init__(self):
        self.gmail_service = None
        self.drive_service = None
        self.sheets_service = None
        
        # API scopes
        self.gmail_scopes = ['https://www.googleapis.com/auth/gmail.readonly']
        self.drive_scopes = ['https://www.googleapis.com/auth/drive.file']
        self.sheets_scopes = ['https://www.googleapis.com/auth/spreadsheets']
    
    def authenticate_from_secrets(self, progress_bar, status_text):
        """Authenticate using credentials file or Streamlit secrets"""
        try:
            status_text.text("Authenticating with Google APIs...")
            progress_bar.progress(10)
            
            # OAuth2 authentication for all services
            combined_scopes = list(set(self.gmail_scopes + self.drive_scopes + self.sheets_scopes))
            
            # Check if running locally or in production
            if os.path.exists('credentials.json'):
                # Local development - use file directly with InstalledAppFlow
                creds = self._oauth2_authenticate_from_file('credentials.json', combined_scopes)
            else:
                # Production - use Streamlit secrets
                creds_data = dict(st.secrets["google_credentials"])
                creds = self._oauth2_authenticate_from_dict(creds_data, combined_scopes)
            
            progress_bar.progress(50)
            
            # Build services
            self.gmail_service = build('gmail', 'v1', credentials=creds)
            self.drive_service = build('drive', 'v3', credentials=creds)
            self.sheets_service = build('sheets', 'v4', credentials=creds)
            
            progress_bar.progress(100)
            status_text.text("Authentication successful!")
            return True
            
        except Exception as e:
            st.error(f"Authentication failed: {str(e)}")
            return False
    
    def _oauth2_authenticate_from_file(self, credentials_path: str, scopes: List[str]) -> Credentials:
        """Handle OAuth2 authentication from credentials.json file"""
        creds = None
        token_file = 'token_combined.json'
        
        # Check for existing token in session state or file
        if 'oauth_token' in st.session_state:
            try:
                creds = Credentials.from_authorized_user_info(st.session_state.oauth_token, scopes)
            except:
                creds = None
        elif os.path.exists(token_file):
            try:
                creds = Credentials.from_authorized_user_file(token_file, scopes)
            except:
                creds = None
        
        # If no valid credentials, run OAuth flow
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                try:
                    creds.refresh(Request())
                except:
                    creds = None
            
            if not creds:
                # Use the credentials file directly with InstalledAppFlow
                flow = InstalledAppFlow.from_client_secrets_file(credentials_path, scopes)
                creds = flow.run_local_server(port=0)
            
            # Save credentials to session state and file
            st.session_state.oauth_token = json.loads(creds.to_json())
            with open(token_file, 'w') as token:
                token.write(creds.to_json())
        
        return creds
    
    def _oauth2_authenticate_from_dict(self, creds_data: dict, scopes: List[str]) -> Credentials:
        """Handle OAuth2 authentication from credentials dictionary (for production)"""
        creds = None
        
        # Check for existing token in session state
        if 'oauth_token' in st.session_state:
            try:
                creds = Credentials.from_authorized_user_info(st.session_state.oauth_token, scopes)
            except:
                creds = None
        
        # If no valid credentials, run OAuth flow
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                try:
                    creds.refresh(Request())
                except:
                    creds = None
            
            if not creds:
                # Create flow from credentials data
                flow = InstalledAppFlow.from_client_config(
                    {"installed": creds_data}, scopes)
                creds = flow.run_local_server(port=0)
            
            # Save credentials to session state
            st.session_state.oauth_token = json.loads(creds.to_json())
        
        return creds
    
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
            st.info(f"Searching Gmail with query: {query}")
            
            # Execute search
            result = self.gmail_service.users().messages().list(
                userId='me', q=query, maxResults=max_results
            ).execute()
            
            messages = result.get('messages', [])
            st.info(f"Gmail search returned {len(messages)} messages")
            
            # Debug: Show some email details
            if messages:
                st.info("Sample emails found:")
                for i, msg in enumerate(messages[:3]):  # Show first 3 emails
                    try:
                        email_details = self._get_email_details(msg['id'])
                        st.write(f"  {i+1}. {email_details['subject']} from {email_details['sender']}")
                    except:
                        st.write(f"  {i+1}. Email ID: {msg['id']}")
            
            return messages
            
        except Exception as e:
            st.error(f"Email search failed: {str(e)}")
            return []
    
    def process_gmail_workflow(self, config: dict, progress_bar, status_text, log_container):
        """Process Gmail attachment download workflow"""
        try:
            status_text.text("Starting Gmail workflow...")
            
            # Search for emails
            emails = self.search_emails(
                sender=config['sender'],
                search_term=config['search_term'],
                days_back=config['days_back'],
                max_results=config['max_results']
            )
            
            progress_bar.progress(25)
            
            if not emails:
                st.warning("No emails found matching criteria")
                return {'success': True, 'processed': 0}
            
            status_text.text(f"Found {len(emails)} emails. Processing attachments...")
            st.info(f"Found {len(emails)} emails matching criteria")
            
            # Create base folder in Drive
            base_folder_name = "Gmail_Attachments"
            base_folder_id = self._create_drive_folder(base_folder_name, config.get('gdrive_folder_id'))
            
            if not base_folder_id:
                st.error("Failed to create base folder in Google Drive")
                return {'success': False, 'processed': 0}
            
            progress_bar.progress(50)
            
            processed_count = 0
            total_attachments = 0
            
            for i, email in enumerate(emails):
                try:
                    status_text.text(f"Processing email {i+1}/{len(emails)}")
                    
                    # Get email details first
                    email_details = self._get_email_details(email['id'])
                    subject = email_details.get('subject', 'No Subject')[:50]
                    sender = email_details.get('sender', 'Unknown')
                    
                    st.info(f"Processing email: {subject} from {sender}")
                    
                    # Get full message with payload
                    message = self.gmail_service.users().messages().get(
                        userId='me', id=email['id'], format='full'
                    ).execute()
                    
                    if not message or not message.get('payload'):
                        st.warning(f"No payload found for email: {subject}")
                        continue
                    
                    # Extract attachments
                    attachment_count = self._extract_attachments_from_email(
                        email['id'], message['payload'], sender, config, base_folder_id
                    )
                    
                    total_attachments += attachment_count
                    if attachment_count > 0:
                        processed_count += 1
                        st.success(f"Found {attachment_count} attachments in: {subject}")
                    else:
                        st.info(f"No matching attachments in: {subject}")
                    
                    progress = 50 + (i + 1) / len(emails) * 45
                    progress_bar.progress(int(progress))
                    
                except Exception as e:
                    st.error(f"Failed to process email {email.get('id', 'unknown')}: {str(e)}")
            
            progress_bar.progress(100)
            status_text.text(f"Gmail workflow completed! Processed {total_attachments} attachments from {processed_count} emails")
            
            return {'success': True, 'processed': total_attachments}
            
        except Exception as e:
            st.error(f"Gmail workflow failed: {str(e)}")
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
            st.error(f"Failed to get email details for {message_id}: {str(e)}")
            return {'id': message_id, 'sender': 'Unknown', 'subject': 'Unknown', 'date': ''}
    
    def _create_drive_folder(self, folder_name: str, parent_folder_id: Optional[str] = None) -> str:
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
            st.error(f"Failed to create folder {folder_name}: {str(e)}")
            return ""
    
    def _extract_attachments_from_email(self, message_id: str, payload: Dict, sender: str, config: dict, base_folder_id: str) -> int:
        """Extract attachments from email with proper folder structure"""
        processed_count = 0
        
        if "parts" in payload:
            for part in payload["parts"]:
                processed_count += self._extract_attachments_from_email(
                    message_id, part, sender, config, base_folder_id
                )
        elif payload.get("filename") and "attachmentId" in payload.get("body", {}):
            filename = payload.get("filename", "")
            
            # Optional attachment filter (not used in Zepto logic, but kept for compatibility)
            if config.get('attachment_filter'):
                if filename.lower() != config['attachment_filter'].lower():
                    return 0
            
            try:
                # Get attachment data
                attachment_id = payload["body"].get("attachmentId")
                att = self.gmail_service.users().messages().attachments().get(
                    userId='me', messageId=message_id, id=attachment_id
                ).execute()
                
                file_data = base64.urlsafe_b64decode(att["data"].encode("UTF-8"))
                
                # Create nested folder structure: Gmail_Attachments -> sender -> search_term -> file_type
                sender_email = sender
                if "<" in sender_email and ">" in sender_email:
                    sender_email = sender_email.split("<")[1].split(">")[0].strip()
                sender_folder_name = self._sanitize_filename(sender_email)
                search_term = config.get('search_term', 'all-attachments')
                search_folder_name = search_term if search_term else "all-attachments"
                file_type_folder = self._classify_extension(filename)
                
                # Create sender folder
                sender_folder_id = self._create_drive_folder(sender_folder_name, base_folder_id)
                
                # Create search term folder
                search_folder_id = self._create_drive_folder(search_folder_name, sender_folder_id)
                
                # Create file type folder within search folder
                type_folder_id = self._create_drive_folder(file_type_folder, search_folder_id)
                
                # Clean filename and make it unique
                clean_filename = self._sanitize_filename(filename)
                final_filename = f"{message_id}_{clean_filename}"
                
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
                    
                    st.info(f"Uploaded: {final_filename}")
                    processed_count = 1
                else:
                    st.info(f"File already exists, skipping: {final_filename}")
                
            except Exception as e:
                st.error(f"Failed to process attachment {filename}: {str(e)}")
        
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
    
    def process_pdf_workflow(self, config: dict, progress_bar, status_text, log_container):
        """Process PDF workflow with LlamaParse"""
        try:
            if not LLAMA_AVAILABLE:
                st.error("LlamaParse not available. Install with: pip install llama-cloud-services")
                return {'success': False, 'processed': 0}
            
            status_text.text("Starting PDF processing workflow...")
            
            # Setup LlamaParse
            os.environ["LLAMA_CLOUD_API_KEY"] = config['llama_api_key']
            extractor = LlamaExtract()
            agent = extractor.get_agent(name=config['llama_agent'])
            
            if agent is None:
                st.error(f"Could not find agent '{config['llama_agent']}'. Check dashboard.")
                return {'success': False, 'processed': 0}
            
            progress_bar.progress(10)
            
            # Get PDF files from Drive
            pdf_files = self._list_drive_files(config['drive_folder_id'], config.get('days_back', None))
            
            progress_bar.progress(30)
            
            if not pdf_files:
                st.warning("No PDF files found in the specified folder")
                return {'success': True, 'processed': 0}
            
            status_text.text(f"Found {len(pdf_files)} PDF files. Processing...")
            st.info(f"Found {len(pdf_files)} PDF files to process")
            
            # Get already processed files from sheet
            processed_files = self._get_processed_files(config['spreadsheet_id'], config['sheet_range'])
            
            processed_count = 0
            all_rows = []
            
            for i, file_info in enumerate(pdf_files):
                try:
                    # Skip if already processed
                    if file_info['name'] in processed_files:
                        st.info(f"Skipping already processed file: {file_info['name']}")
                        continue
                        
                    status_text.text(f"Processing PDF {i+1}/{len(pdf_files)}: {file_info['name']}")
                    
                    # Download PDF
                    pdf_data = self._download_from_drive(file_info['id'])
                    
                    if not pdf_data:
                        st.warning(f"Failed to download PDF: {file_info['name']}")
                        continue
                    
                    # Save to temporary file
                    with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as temp_file:
                        temp_file.write(pdf_data)
                        temp_path = temp_file.name
                    
                    # Extract data
                    result = agent.extract(temp_path)
                    extracted_data = result.data
                    
                    # Clean up temp file
                    os.unlink(temp_path)
                    
                    # Process extracted data
                    rows = self._process_extracted_data(extracted_data, file_info)
                    all_rows.extend(rows)
                    
                    processed_count += 1
                    st.success(f"Processed: {file_info['name']} - Extracted {len(rows)} rows")
                    
                    progress = 30 + (i + 1) / len(pdf_files) * 60
                    progress_bar.progress(int(progress))
                    
                except Exception as e:
                    st.error(f"Failed to process PDF {file_info.get('name', 'unknown')}: {str(e)}")
            
            # Save all rows to sheets at once
            if all_rows:
                self._save_to_sheets(
                    config['spreadsheet_id'],
                    config['sheet_range'],
                    all_rows
                )
            
            progress_bar.progress(100)
            status_text.text(f"PDF workflow completed! Processed {processed_count} PDFs with {len(all_rows)} rows")
            
            return {'success': True, 'processed': processed_count}
            
        except Exception as e:
            st.error(f"PDF workflow failed: {str(e)}")
            return {'success': False, 'processed': 0}
    
    def _get_processed_files(self, spreadsheet_id: str, sheet_range: str) -> List[str]:
        """Get list of already processed files from Google Sheet to avoid duplicates"""
        try:
            result = self.sheets_service.spreadsheets().values().get(
                spreadsheetId=spreadsheet_id,
                range=f"{sheet_range}!A:Z",
                majorDimension="ROWS"
            ).execute()
            
            values = result.get('values', [])
            if len(values) <= 1:  # Only headers or empty
                return []
            
            # Assuming source_file is in column A (index 0)
            processed_files = []
            for row in values[1:]:  # Skip header row
                if row and len(row) > 0:
                    processed_files.append(row[0])
            
            return processed_files
            
        except Exception as e:
            st.warning(f"Could not retrieve processed files list: {str(e)}")
            return []
    
    def _list_drive_files(self, folder_id: str, days_back: Optional[int] = None) -> List[Dict]:
        """List all PDF files in a Google Drive folder, optionally filtered by days back"""
        try:
            query = f"'{folder_id}' in parents and mimeType='application/pdf' and trashed=false"
            
            if days_back:
                start_date = (datetime.now() - timedelta(days=days_back)).isoformat()
                query += f" and modifiedTime > '{start_date}'"
            
            files = []
            page_token = None
            
            while True:
                results = self.drive_service.files().list(
                    q=query,
                    fields="nextPageToken, files(id, name, createdTime, modifiedTime)",
                    orderBy="modifiedTime desc",
                    pageToken=page_token,
                    pageSize=100
                ).execute()
                
                files.extend(results.get('files', []))
                page_token = results.get('nextPageToken', None)
                
                if page_token is None:
                    break
            
            st.info(f"Found {len(files)} PDF files")
            return files
            
        except Exception as e:
            st.error(f"Failed to list files in folder {folder_id}: {str(e)}")
            return []
    
    def _download_from_drive(self, file_id: str) -> bytes:
        """Download a file from Google Drive"""
        try:
            request = self.drive_service.files().get_media(fileId=file_id)
            return request.execute()
        except Exception as e:
            st.error(f"Failed to download file {file_id}: {str(e)}")
            return b""
    
    def _process_extracted_data(self, extracted_data: Dict, file_info: Dict) -> List[Dict]:
        """Process extracted data using Zepto logic based on the provided JSON structure"""
        rows = []
        
        # Extract common fields
        common_data = {
            "source_file": file_info['name'],
            "processed_date": time.strftime("%Y-%m-%d %H:%M:%S"),
            "drive_file_id": file_info['id'],
            "company_name": extracted_data.get("company_name", ""),
            "company_address": extracted_data.get("company_address", ""),
            "shipping_address": extracted_data.get("shipping_address", ""),
            "grn_number": extracted_data.get("grn_number", ""),
            "grn_date": extracted_data.get("grn_date", ""),
            "po_number": extracted_data.get("po_number", ""),
            "vendor_invoice_no": extracted_data.get("vendor_invoice_no", ""),
            "gstin_company": extracted_data.get("gstin_company", ""),
            "shipment_number": extracted_data.get("shipment_number", "")
        }
        
        # Process items
        if "items" in extracted_data and isinstance(extracted_data["items"], list):
            for item in extracted_data["items"]:
                row = common_data.copy()
                row.update({
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
                    "value_inr": item.get("value_inr", "")
                })
                rows.append(row)
        
        return rows
    
    def _save_to_sheets(self, spreadsheet_id: str, sheet_name: str, rows: List[Dict]):
        """Save data to Google Sheets with proper header management (append only, no replacement)"""
        try:
            if not rows:
                return
            
            # Get existing headers and data
            existing_headers = self._get_sheet_headers(spreadsheet_id, sheet_name)
            
            # Get all unique headers from new data
            new_headers = list(set().union(*(row.keys() for row in rows)))
            
            # Combine headers (existing + new unique ones)
            if existing_headers:
                all_headers = existing_headers.copy()
                for header in new_headers:
                    if header not in all_headers:
                        all_headers.append(header)
                
                # Update headers if new ones were added
                if len(all_headers) > len(existing_headers):
                    self._update_headers(spreadsheet_id, sheet_name, all_headers)
            else:
                # No existing headers, create them
                all_headers = new_headers
                self._update_headers(spreadsheet_id, sheet_name, all_headers)
            
            # Append new rows
            values = [[row.get(h, "") for h in all_headers] for row in rows]
            self._append_to_google_sheet(spreadsheet_id, sheet_name, values)
            
        except Exception as e:
            st.error(f"Failed to save to sheets: {str(e)}")
    
    def _get_sheet_headers(self, spreadsheet_id: str, sheet_name: str) -> List[str]:
        """Get existing headers from Google Sheet"""
        try:
            result = self.sheets_service.spreadsheets().values().get(
                spreadsheetId=spreadsheet_id,
                range=f"{sheet_name}!A1:Z1",
                majorDimension="ROWS"
            ).execute()
            values = result.get('values', [])
            return values[0] if values else []
        except Exception as e:
            st.info(f"No existing headers found: {str(e)}")
            return []
    
    def _update_headers(self, spreadsheet_id: str, sheet_name: str, headers: List[str]) -> bool:
        """Update the header row with new columns"""
        try:
            body = {'values': [headers]}
            result = self.sheets_service.spreadsheets().values().update(
                spreadsheetId=spreadsheet_id,
                range=f"{sheet_name}!A1:{chr(64 + len(headers))}1",
                valueInputOption='USER_ENTERED',
                body=body
            ).execute()
            st.info(f"Updated headers with {len(headers)} columns")
            return True
        except Exception as e:
            st.error(f"Failed to update headers: {str(e)}")
            return False
    
    def _append_to_google_sheet(self, spreadsheet_id: str, range_name: str, values: List[List[Any]]) -> bool:
        """Append data to a Google Sheet with retry mechanism"""
        max_retries = 3
        wait_time = 2
        
        for attempt in range(1, max_retries + 1):
            try:
                body = {'values': values}
                result = self.sheets_service.spreadsheets().values().append(
                    spreadsheetId=spreadsheet_id, 
                    range=range_name,
                    valueInputOption='USER_ENTERED', 
                    body=body
                ).execute()
                
                updated_cells = result.get('updates', {}).get('updatedCells', 0)
                st.info(f"Appended {updated_cells} cells to Google Sheet")
                return True
            except Exception as e:
                if attempt < max_retries:
                    st.warning(f"Failed to append to Google Sheet (attempt {attempt}/{max_retries}): {str(e)}")
                    time.sleep(wait_time)
                else:
                    st.error(f"Failed to append to Google Sheet after {max_retries} attempts: {str(e)}")
                    return False
        return False

def main():
    st.title("⚡ Zepto Automation Dashboard")
    st.markdown("Automate Gmail attachment downloads and PDF processing workflows")
    
    # Initialize session state for configuration
    if 'gmail_config' not in st.session_state:
        st.session_state.gmail_config = {
            'sender': "aws-reports@moreretail.in",
            'search_term': "in:spam ",
            'days_back': 30,
            'max_results': 1000,
            'attachment_filter': "",
            'gdrive_folder_id': "1gZoNjdGarwMD5-Ci3uoqjNZZ8bTNyVoy"
        }
    
    if 'pdf_config' not in st.session_state:
        st.session_state.pdf_config = {
            'drive_folder_id': "18LRA2eMtHVPXQ2lQa5tuaYk9CAYNVJsW",
            'llama_api_key': "llx-FccnxqEJsqrNTltO8u0zByspDJ7MawqnbI8KGKffEDGzHyoa",
            'llama_agent': "More retail Agent",
            'spreadsheet_id': "16y9DAK2tVHgnZNnPeRoSSPPE2NcspW_qqMF8ZR8OOC0",
            'sheet_range': "mraws",
            'days_back': 1
        }
    
    # Initialize workflow execution state
    if 'workflow_running' not in st.session_state:
        st.session_state.workflow_running = False
    if 'workflow_type' not in st.session_state:
        st.session_state.workflow_type = None
    if 'logs' not in st.session_state:
        st.session_state.logs = []
    
    # Configuration section in sidebar
    st.sidebar.header("Configuration")
    
    # Use forms to prevent auto-execution on input changes
    with st.sidebar.form("gmail_config_form"):
        st.subheader("Gmail Settings")
        gmail_sender = st.text_input("Sender Email", value=st.session_state.gmail_config['sender'])
        gmail_search = st.text_input("Search Term", value=st.session_state.gmail_config['search_term'])
        gmail_days = st.number_input("Days Back", value=st.session_state.gmail_config['days_back'], min_value=1)
        gmail_max = st.number_input("Max Results", value=st.session_state.gmail_config['max_results'], min_value=1)
        gmail_filter = st.text_input("Attachment Filter (optional)", value=st.session_state.gmail_config['attachment_filter'])
        gmail_folder = st.text_input("Google Drive Folder ID", value=st.session_state.gmail_config['gdrive_folder_id'])
        
        gmail_submit = st.form_submit_button("Update Gmail Settings")
        
        if gmail_submit:
            st.session_state.gmail_config = {
                'sender': gmail_sender,
                'search_term': gmail_search,
                'days_back': gmail_days,
                'max_results': gmail_max,
                'attachment_filter': gmail_filter,
                'gdrive_folder_id': gmail_folder
            }
            st.success("Gmail settings updated!")
    
    with st.sidebar.form("pdf_config_form"):
        st.subheader("PDF Processing Settings")
        pdf_folder = st.text_input("PDF Drive Folder ID", value=st.session_state.pdf_config['drive_folder_id'])
        pdf_api_key = st.text_input("LlamaParse API Key", value=st.session_state.pdf_config['llama_api_key'], type="password")
        pdf_agent = st.text_input("LlamaParse Agent", value=st.session_state.pdf_config['llama_agent'])
        pdf_sheet_id = st.text_input("Spreadsheet ID", value=st.session_state.pdf_config['spreadsheet_id'])
        pdf_sheet_range = st.text_input("Sheet Range", value=st.session_state.pdf_config['sheet_range'])
        pdf_days = st.number_input("PDF Days Back", value=st.session_state.pdf_config['days_back'], min_value=1)
        
        pdf_submit = st.form_submit_button("Update PDF Settings")
        
        if pdf_submit:
            st.session_state.pdf_config = {
                'drive_folder_id': pdf_folder,
                'llama_api_key': pdf_api_key,
                'llama_agent': pdf_agent,
                'spreadsheet_id': pdf_sheet_id,
                'sheet_range': pdf_sheet_range,
                'days_back': pdf_days
            }
            st.success("PDF settings updated!")
    
    # Add a separator
    st.sidebar.markdown("---")
    st.sidebar.markdown("### Execute Workflows")
    st.sidebar.info("Configure settings above, then choose a workflow to run")
    
    # Main content area - workflow buttons
    st.header("Choose Workflow")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("Gmail Workflow Only", use_container_width=True, disabled=st.session_state.workflow_running):
            st.session_state.workflow_type = "gmail"
            st.session_state.workflow_running = False  # Reset to show start button
    
    with col2:
        if st.button("PDF Workflow Only", use_container_width=True, disabled=st.session_state.workflow_running):
            st.session_state.workflow_type = "pdf"
            st.session_state.workflow_running = False  # Reset to show start button
    
    with col3:
        if st.button("Combined Workflow", use_container_width=True, disabled=st.session_state.workflow_running):
            st.session_state.workflow_type = "combined"
            st.session_state.workflow_running = False  # Reset to show start button
    
    # Show current configuration preview
    if not st.session_state.workflow_type:
        st.header("Current Configuration")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Gmail Configuration")
            st.json(st.session_state.gmail_config)
        
        with col2:
            st.subheader("PDF Configuration")
            # Hide API key in display
            display_pdf_config = st.session_state.pdf_config.copy()
            display_pdf_config['llama_api_key'] = "*" * len(display_pdf_config['llama_api_key'])
            st.json(display_pdf_config)
        
        st.info("Configure your settings in the sidebar, then select a workflow above to begin automation")
        return
    
    # Show selected workflow and start button
    st.header(f"Selected Workflow: {st.session_state.workflow_type.upper()}")
    
    # Add start button
    if not st.session_state.workflow_running:
        if st.button("Start Workflow", type="primary", use_container_width=True):
            st.session_state.workflow_running = True
            st.session_state.logs = []  # Clear previous logs
            st.rerun()
    
    # If workflow is running, execute it
    if st.session_state.workflow_running:
        # Create automation instance
        automation = ZeptoAutomation()
        
        # Authentication section
        st.header("Authentication")
        auth_progress = st.progress(0)
        auth_status = st.empty()
        
        if automation.authenticate_from_secrets(auth_progress, auth_status):
            st.success("Authentication successful!")
            
            # Workflow execution section
            st.header("Workflow Execution")
            
            # Progress tracking
            main_progress = st.progress(0)
            main_status = st.empty()
            
            # Log container
            st.subheader("Real-time Logs")
            log_container = st.empty()
            
            # Custom log handler
            log_handler = StreamlitLogHandler(log_container)
            log_handler.setLevel(logging.INFO)
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            log_handler.setFormatter(formatter)
            
            # Add handler to root logger
            root_logger = logging.getLogger()
            root_logger.addHandler(log_handler)
            root_logger.setLevel(logging.INFO)
            
            if st.session_state.workflow_type == "gmail":
                result = automation.process_gmail_workflow(
                    st.session_state.gmail_config, main_progress, main_status, log_container
                )
                if result['success']:
                    st.success(f"Gmail workflow completed! Processed {result['processed']} attachments")
                else:
                    st.error("Gmail workflow failed")
            
            elif st.session_state.workflow_type == "pdf":
                result = automation.process_pdf_workflow(
                    st.session_state.pdf_config, main_progress, main_status, log_container
                )
                if result['success']:
                    st.success(f"PDF workflow completed! Processed {result['processed']} PDFs")
                else:
                    st.error("PDF workflow failed")
            
            elif st.session_state.workflow_type == "combined":
                st.info("Running combined workflow...")
                
                # Step 1: Gmail workflow
                st.subheader("Step 1: Gmail Attachment Download")
                gmail_result = automation.process_gmail_workflow(
                    st.session_state.gmail_config, main_progress, main_status, log_container
                )
                
                if gmail_result['success']:
                    st.success(f"Gmail step completed! Processed {gmail_result['processed']} attachments")
                    
                    # Small delay
                    time.sleep(2)
                    
                    # Step 2: PDF processing
                    st.subheader("Step 2: PDF Processing")
                    pdf_result = automation.process_pdf_workflow(
                        st.session_state.pdf_config, main_progress, main_status, log_container
                    )
                    
                    if pdf_result['success']:
                        st.success(f"Combined workflow completed successfully!")
                        st.balloons()
                    else:
                        st.error("PDF processing step failed")
                else:
                    st.error("Gmail step failed - stopping combined workflow")
            
            # Remove handler after workflow completion
            root_logger.removeHandler(log_handler)
        
        # Reset workflow state after completion
        st.session_state.workflow_running = False
    
    # Reset workflow with confirmation
    st.markdown("---")
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Reset Workflow", use_container_width=True):
            st.session_state.workflow_type = None
            st.session_state.workflow_running = False
            st.rerun()
    with col2:
        if st.button("Reset All Settings", use_container_width=True, type="secondary"):
            # Reset all configurations
            for key in ['gmail_config', 'pdf_config', 'workflow_type', 'workflow_running']:
                if key in st.session_state:
                    del st.session_state[key]
            st.rerun()

if __name__ == "__main__":
    main()
