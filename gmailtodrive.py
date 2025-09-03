#!/usr/bin/env python3
"""
Automated Gmail Attachment Downloader to Google Drive
Downloads attachments from specified Gmail sender/search terms and uploads to Google Drive
"""

import os
import base64
import re
import uuid
import json
import time
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional

from google.oauth2.credentials import Credentials
from google.oauth2 import service_account
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from googleapiclient.http import MediaIoBaseUpload
import io

# Configure logging with UTF-8 encoding for Windows compatibility
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('gmail_gdrive_automation.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class GmailGDriveAutomation:
    def __init__(self, credentials_path: str, gdrive_folder_id: Optional[str] = None):
        """
        Initialize the automation script
        
        Args:
            credentials_path: Path to the Google credentials JSON file
            gdrive_folder_id: Google Drive folder ID where files should be uploaded (optional)
        """
        self.credentials_path = credentials_path
        self.gdrive_folder_id = gdrive_folder_id
        self.gmail_service = None
        self.drive_service = None
        
        # Gmail and Drive API scopes
        self.gmail_scopes = ['https://www.googleapis.com/auth/gmail.readonly']
        self.drive_scopes = ['https://www.googleapis.com/auth/drive.file']
        
    def authenticate(self):
        """Authenticate with both Gmail and Google Drive APIs"""
        try:
            # Load credentials from JSON file
            with open(self.credentials_path, 'r') as f:
                creds_data = json.load(f)
            
            # Check if it's a service account or OAuth2 credentials
            if 'type' in creds_data and creds_data['type'] == 'service_account':
                # Service account authentication
                gmail_creds = service_account.Credentials.from_service_account_file(
                    self.credentials_path, scopes=self.gmail_scopes)
                drive_creds = service_account.Credentials.from_service_account_file(
                    self.credentials_path, scopes=self.drive_scopes)
            else:
                # OAuth2 authentication
                gmail_creds = self._oauth2_authenticate(self.gmail_scopes, 'gmail')
                drive_creds = self._oauth2_authenticate(self.drive_scopes, 'drive')
            
            # Build services
            self.gmail_service = build('gmail', 'v1', credentials=gmail_creds)
            self.drive_service = build('drive', 'v3', credentials=drive_creds)
            
            logger.info("[SUCCESS] Successfully authenticated with Gmail and Google Drive")
            return True
            
        except Exception as e:
            logger.error(f"[ERROR] Authentication failed: {str(e)}")
            return False
    
    def _oauth2_authenticate(self, scopes: List[str], service_name: str) -> Credentials:
        """Handle OAuth2 authentication flow"""
        creds = None
        token_file = f'token_{service_name}.json'
        
        # Check for existing token
        if os.path.exists(token_file):
            creds = Credentials.from_authorized_user_file(token_file, scopes)
        
        # If no valid credentials, run OAuth flow
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file(
                    self.credentials_path, scopes)
                creds = flow.run_local_server(port=0)
            
            # Save credentials for next run
            with open(token_file, 'w') as token:
                token.write(creds.to_json())
        
        return creds
    
    def sanitize_filename(self, filename: str) -> str:
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
    
    def classify_extension(self, filename: str) -> str:
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
    
    def search_emails(self, sender: str = "", search_term: str = "", 
                     days_back: int = 7, max_results: int = 50) -> List[Dict]:
        """
        Search for emails with attachments
        
        Args:
            sender: Email address to search from
            search_term: Keywords to search for in emails
            days_back: How many days back to search
            max_results: Maximum number of emails to process
            
        Returns:
            List of email message dictionaries
        """
        try:
            # Build search query
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
            
            # Add date filter
            start_date = datetime.now() - timedelta(days=days_back)
            query_parts.append(f"after:{start_date.strftime('%Y/%m/%d')}")
            
            query = " ".join(query_parts)
            logger.info(f"[SEARCH] Searching Gmail with query: {query}")
            
            # Execute search
            result = self.gmail_service.users().messages().list(
                userId='me', q=query, maxResults=max_results
            ).execute()
            
            messages = result.get('messages', [])
            logger.info(f"[SEARCH] Found {len(messages)} emails matching criteria")
            
            return messages
            
        except Exception as e:
            logger.error(f"[ERROR] Email search failed: {str(e)}")
            return []
    
    def get_email_details(self, message_id: str) -> Dict:
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
            logger.error(f"[ERROR] Failed to get email details for {message_id}: {str(e)}")
            return {}
    
    def create_drive_folder(self, folder_name: str, parent_folder_id: Optional[str] = None) -> str:
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
                logger.info(f"[DRIVE] Using existing folder: {folder_name} (ID: {folder_id})")
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
            logger.info(f"[DRIVE] Created Google Drive folder: {folder_name} (ID: {folder_id})")
            
            return folder_id
            
        except Exception as e:
            logger.error(f"[ERROR] Failed to create folder {folder_name}: {str(e)}")
            return ""
    
    def upload_to_drive(self, file_data: bytes, filename: str, folder_id: str) -> bool:
        """Upload file to Google Drive"""
        try:
            # Check if file already exists
            query = f"name='{filename}' and '{folder_id}' in parents and trashed=false"
            existing = self.drive_service.files().list(q=query, fields='files(id, name)').execute()
            files = existing.get('files', [])
            
            if files:
                logger.info(f"[DRIVE] File already exists, skipping: {filename}")
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
            
            logger.info(f"[DRIVE] Uploaded to Drive: {filename}")
            return True
            
        except Exception as e:
            logger.error(f"[ERROR] Failed to upload {filename}: {str(e)}")
            return False
    
    def process_attachment(self, message_id: str, part: Dict, sender_info: Dict, 
                          search_term: str, base_folder_id: str) -> bool:
        """Process and upload a single attachment"""
        try:
            # Get filename
            filename = part.get("filename", "")
            if not filename:
                return False
            
            # Clean filename
            # Clean filename (keep as-is, only sanitize for invalid chars)
            final_filename = self.sanitize_filename(filename)

            # Get attachment data
            attachment_id = part["body"].get("attachmentId")
            if not attachment_id:
                return False
            
            att = self.gmail_service.users().messages().attachments().get(
                userId='me', messageId=message_id, id=attachment_id
            ).execute()
            
            if not att.get("data"):
                return False
            
            # Decode file data
            file_data = base64.urlsafe_b64decode(att["data"].encode("UTF-8"))
            
            # Create folder structure in Drive
            sender_email = sender_info.get('sender', 'Unknown')
            if "<" in sender_email and ">" in sender_email:
                sender_email = sender_email.split("<")[1].split(">")[0].strip()
            
            sender_folder_name = self.sanitize_filename(sender_email)
            search_folder_name = search_term if search_term else "all-attachments"
            file_type_folder = self.classify_extension(filename)
            
            # Create nested folder structure
            sender_folder_id = self.create_drive_folder(sender_folder_name, base_folder_id)
            search_folder_id = self.create_drive_folder(search_folder_name, sender_folder_id)
            type_folder_id = self.create_drive_folder(file_type_folder, search_folder_id)
            
            # Upload file
            success = self.upload_to_drive(file_data, final_filename, type_folder_id)
            
            if success:
                logger.info(f"[SUCCESS] Processed attachment: {filename}")
            
            return success
            
        except Exception as e:
            logger.error(f"[ERROR] Failed to process attachment {part.get('filename', 'unknown')}: {str(e)}")
            return False
    
    def extract_attachments_from_email(self, message_id: str, payload: Dict, 
                                     sender_info: Dict, search_term: str, 
                                     base_folder_id: str) -> int:
        """Recursively extract all attachments from an email"""
        processed_count = 0
        
        # Process parts if they exist
        if "parts" in payload:
            for part in payload["parts"]:
                processed_count += self.extract_attachments_from_email(
                    message_id, part, sender_info, search_term, base_folder_id
                )
        
        # Process this part if it's an attachment
        elif payload.get("filename") and "attachmentId" in payload.get("body", {}):
            if self.process_attachment(message_id, payload, sender_info, search_term, base_folder_id):
                processed_count += 1
        
        return processed_count
    
    def process_emails(self, emails: List[Dict], search_term: str = "") -> Dict:
        """Process all emails and download their attachments"""
        stats = {
            'total_emails': len(emails),
            'processed_emails': 0,
            'total_attachments': 0,
            'successful_uploads': 0,
            'failed_uploads': 0
        }
        
        if not emails:
            logger.info("[INFO] No emails to process")
            return stats
        
        # Create base folder in Drive
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_folder_name = f"Gmail_Attachments"
        base_folder_id = self.create_drive_folder(base_folder_name, self.gdrive_folder_id)
        if not base_folder_id:
            logger.error("[ERROR] Failed to create base folder in Google Drive")
            return stats
        
        logger.info(f"[PROCESS] Processing {len(emails)} emails...")
        
        for i, email in enumerate(emails, 1):
            try:
                logger.info(f"[PROCESS] Processing email {i}/{len(emails)}")
                
                # Get email details
                sender_info = self.get_email_details(email['id'])
                if not sender_info:
                    continue
                
                # Get full message
                message = self.gmail_service.users().messages().get(
                    userId='me', id=email['id']
                ).execute()
                
                if not message or not message.get('payload'):
                    continue
                
                # Extract attachments
                attachment_count = self.extract_attachments_from_email(
                    email['id'], message['payload'], sender_info, search_term, base_folder_id
                )
                
                stats['total_attachments'] += attachment_count
                stats['successful_uploads'] += attachment_count
                stats['processed_emails'] += 1
                
                subject = sender_info.get('subject', 'No Subject')[:50]
                logger.info(f"[PROCESS] Found {attachment_count} attachments in email: {subject}")
                
            except Exception as e:
                logger.error(f"[ERROR] Failed to process email {email.get('id', 'unknown')}: {str(e)}")
                stats['failed_uploads'] += 1
        
        return stats
    
    def run_automation(self, sender: str = "", search_term: str = "", 
                      days_back: int = 7, max_results: int = 50):
        """
        Main automation function
        
        Args:
            sender: Email address to search from
            search_term: Keywords to search for
            days_back: How many days back to search
            max_results: Maximum number of emails to process
        """
        logger.info("[START] Starting Gmail to Google Drive automation")
        logger.info(f"[CONFIG] Parameters: sender='{sender}', search_term='{search_term}', days_back={days_back}")
        
        # Authenticate
        if not self.authenticate():
            return
        
        # Search for emails
        emails = self.search_emails(sender, search_term, days_back, max_results)
        
        if not emails:
            logger.info("[INFO] No emails found matching criteria")
            return
        
        # Process emails and upload attachments
        stats = self.process_emails(emails, search_term)
        
        # Report results
        logger.info("[COMPLETE] AUTOMATION COMPLETE!")
        logger.info(f"[STATS] Emails processed: {stats['processed_emails']}/{stats['total_emails']}")
        logger.info(f"[STATS] Total attachments: {stats['total_attachments']}")
        logger.info(f"[STATS] Successful uploads: {stats['successful_uploads']}")
        logger.info(f"[STATS] Failed uploads: {stats['failed_uploads']}")

def main():
    """Run the automation once (no scheduling)"""
    
    print("=== Gmail to Google Drive Automation ===")
    print("Running one-time execution (no scheduling)")
    print()
    
    # Configuration - MODIFY THESE VALUES
    CONFIG = {
        'credentials_path': 'C:\\Users\\Lucifer\\Desktop\\New folder\\TBD\GRN\\MoreRetail Automation\\credentials.json',  # Path to your Google credentials JSON
        'gdrive_folder_id': '1gZoNjdGarwMD5-Ci3uoqjNZZ8bTNyVoy',  # Optional: Google Drive folder ID to upload to
        'sender': 'aws-reports@moreretail.in',  # Email address to search from
        'search_term': 'in:spam ',  # Keywords to search for
        'days_back': 10, # How many days to search
        'max_results': 1000  # Maximum number of emails to process
    }
    
    # Validate configuration
    if not os.path.exists(CONFIG['credentials_path']):
        print(f"[ERROR] Credentials file not found: {CONFIG['credentials_path']}")
        print()
        print("SETUP INSTRUCTIONS:")
        print("1. Go to https://console.cloud.google.com")
        print("2. Create a new project or select existing one")
        print("3. Enable Gmail API and Google Drive API")
        print("4. Go to 'Credentials' > 'Create Credentials' > 'OAuth client ID'")
        print("5. Choose 'Desktop application' as application type")
        print("6. Download the JSON file and save it as 'credentials.json' in this folder")
        print()
        print("Required packages (install with pip):")
        print("pip install google-auth google-auth-oauthlib google-auth-httplib2 google-api-python-client")
        return
    
    # Initialize automation
    automation = GmailGDriveAutomation(
        credentials_path=CONFIG['credentials_path'],
        gdrive_folder_id=CONFIG['gdrive_folder_id']
    )
    
    # Run the automation once
    automation.run_automation(
        sender=CONFIG['sender'],
        search_term=CONFIG['search_term'],
        days_back=CONFIG['days_back'],
        max_results=CONFIG['max_results']
    )
    
    print("\n[INFO] Automation completed. Check the log file for details.")

if __name__ == "__main__":
    main()