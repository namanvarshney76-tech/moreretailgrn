#!/usr/bin/env python3
"""
Google Drive PDF Processor with LlamaParse to Google Sheets
Processes PDFs from Google Drive with LlamaParse and appends data to Google Sheets
"""

import os
import json
import time
import logging
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any
from io import BytesIO

from google.oauth2.credentials import Credentials
from google.oauth2 import service_account
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# Add LlamaParse import
try:
    from llama_cloud_services import LlamaExtract
    LLAMA_AVAILABLE = True
except ImportError:
    LLAMA_AVAILABLE = False
    print("LlamaParse not available. Install with: pip install llama-cloud-services")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('drive_pdf_processor.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class DrivePDFProcessor:
    def __init__(self, credentials_path: str):
        """
        Initialize the PDF processor
        
        Args:
            credentials_path: Path to the Google credentials JSON file
        """
        self.credentials_path = credentials_path
        self.drive_service = None
        self.sheets_service = None
        
        # API scopes - updated to use the correct format
        self.drive_scopes = ['https://www.googleapis.com/auth/drive.readonly']
        self.sheets_scopes = ['https://www.googleapis.com/auth/spreadsheets']
        
    def authenticate(self):
        """Authenticate with Google Drive and Google Sheets APIs"""
        try:
            # Load credentials from JSON file
            with open(self.credentials_path, 'r') as f:
                creds_data = json.load(f)
            
            # Check if it's a service account or OAuth2 credentials
            if 'type' in creds_data and creds_data['type'] == 'service_account':
                print("🔑 Using service account authentication")
                # Service account authentication
                credentials = service_account.Credentials.from_service_account_file(
                    self.credentials_path,
                    scopes=self.drive_scopes + self.sheets_scopes
                )
                
                # Build services with the same credentials
                self.drive_service = build('drive', 'v3', credentials=credentials)
                self.sheets_service = build('sheets', 'v4', credentials=credentials)
                
            else:
                print("🔑 Using OAuth2 authentication")
                # OAuth2 authentication - use combined scopes
                combined_scopes = self.drive_scopes + self.sheets_scopes
                creds = self._oauth2_authenticate(combined_scopes, 'combined')
                
                # Build services with the same credentials
                self.drive_service = build('drive', 'v3', credentials=creds)
                self.sheets_service = build('sheets', 'v4', credentials=creds)
            
            logger.info("[SUCCESS] Successfully authenticated with Google Drive and Sheets")
            print("✅ Authentication successful")
            return True
            
        except Exception as e:
            logger.error(f"[ERROR] Authentication failed: {str(e)}")
            print(f"❌ Authentication failed: {str(e)}")
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
    
    def list_drive_files(self, folder_id: str, days_back: int = None) -> List[Dict]:
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
                logger.info(f"[DRIVE] Applying date filter: createdTime >= {start_str}")
            
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

            print(f"📂 Found {len(files)} PDF files in folder")
            logger.info(f"[DRIVE] Found {len(files)} PDF files in folder {folder_id}")
            
            # Print file names for debugging
            for file in files:
                print(f"   - {file['name']}")
                logger.info(f"[DRIVE] Found file: {file['name']} (ID: {file['id']})")
            
            return files

        except Exception as e:
            print(f"❌ Failed to list files: {str(e)}")
            logger.error(f"[ERROR] Failed to list files in folder {folder_id}: {str(e)}")
            return []
    
    def download_from_drive(self, file_id: str, file_name: str) -> bytes:
        """Download a file from Google Drive"""
        try:
            print(f"⬇️ Downloading: {file_name}")
            request = self.drive_service.files().get_media(fileId=file_id)
            file_data = request.execute()
            print(f"✅ Downloaded: {file_name}")
            return file_data
        except Exception as e:
            print(f"❌ Failed to download {file_name}: {str(e)}")
            logger.error(f"[ERROR] Failed to download file {file_name}: {str(e)}")
            return b""
    
    def append_to_google_sheet(self, spreadsheet_id: str, range_name: str, values: List[List[Any]]):
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
            print(f"💾 Appended {updated_cells} cells to Google Sheet")
            logger.info(f"[SHEETS] Appended {updated_cells} cells to Google Sheet")
            return True
            
        except Exception as e:
            print(f"❌ Failed to append to Google Sheet: {str(e)}")
            logger.error(f"[ERROR] Failed to append to Google Sheet: {str(e)}")
            return False
    
    def get_sheet_headers(self, spreadsheet_id: str, range_name: str) -> List[str]:
        """Get existing headers from Google Sheet"""
        try:
            result = self.sheets_service.spreadsheets().values().get(
                spreadsheetId=spreadsheet_id,
                range=range_name,
                majorDimension="ROWS"
            ).execute()
            
            values = result.get('values', [])
            if values and len(values) > 0:
                return values[0]  # Return header row
            return []
            
        except Exception as e:
            print(f"ℹ️ No existing headers found or error: {str(e)}")
            logger.error(f"[ERROR] Failed to get sheet headers: {str(e)}")
            return []
    
    def clean_number(self, val):
        """Round floats to 2 decimals, keep integers as-is"""
        if isinstance(val, float):
            return round(val, 2)
        return val
    
    def flatten_json(self, extracted_data: Dict) -> List[Dict]:
        """
        Convert extracted_data into row format for Google Sheets.
        Each row represents an item with invoice/GRN metadata.
        """
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
        """Retry-safe extraction to handle server disconnections"""
        for attempt in range(1, retries + 1):
            try:
                print(f"🔍 Extracting data (attempt {attempt}/{retries})...")
                result = agent.extract(file_path)
                print("✅ Extraction successful")
                return result
            except Exception as e:
                print(f"⚠️ Attempt {attempt} failed: {e}")
                logger.error(f"⚠️ Attempt {attempt} failed for {file_path}: {e}")
                time.sleep(wait_time)
        raise Exception(f"❌ Extraction failed after {retries} attempts for {file_path}")
    
    def process_pdfs(self, drive_folder_id: str, api_key: str, agent_name: str, 
                    spreadsheet_id: str, sheet_range: str = "Sheet1", days_back: int = None) -> Dict:
        """
        Process PDFs from Google Drive with LlamaParse and save to Google Sheets
        
        Args:
            drive_folder_id: Google Drive folder ID containing PDFs
            api_key: LlamaParse API key
            agent_name: LlamaParse agent name
            spreadsheet_id: Google Sheets ID to save results to
            sheet_range: Sheet range to update (default: "Sheet1")
            days_back: Number of days back to process PDFs (1 = today, 2 = today + yesterday, etc.)
        """
        stats = {
            'total_pdfs': 0,
            'processed_pdfs': 0,
            'failed_pdfs': 0,
            'rows_added': 0
        }
        
        if not LLAMA_AVAILABLE:
            print("❌ LlamaParse not available. Install with: pip install llama-cloud-services")
            logger.error("[ERROR] LlamaParse not available. Install with: pip install llama-cloud-services")
            return stats
        
        try:
            # Set up LlamaParse
            print("🔑 Setting up LlamaParse...")
            os.environ["LLAMA_CLOUD_API_KEY"] = api_key
            extractor = LlamaExtract()
            agent = extractor.get_agent(name=agent_name)
            
            if agent is None:
                print(f"❌ Could not find agent '{agent_name}'. Check dashboard.")
                logger.error(f"[ERROR] Could not find agent '{agent_name}'. Check dashboard.")
                return stats
            
            print("✅ LlamaParse agent found")
            
            # Get PDF files from Drive
            print(f"📂 Searching for PDFs in folder ID: {drive_folder_id}")
            pdf_files = self.list_drive_files(drive_folder_id, days_back=days_back)
            stats['total_pdfs'] = len(pdf_files)
            
            if not pdf_files:
                print("❌ No PDF files found in the specified folder")
                logger.info("[INFO] No PDF files found in the specified folder")
                return stats
            
            print(f"📊 Found {len(pdf_files)} PDF files to process")
            
            # Get existing headers from Google Sheet to maintain consistency
            print("📋 Checking existing sheet headers...")
            existing_headers = self.get_sheet_headers(spreadsheet_id, sheet_range)
            
            # Write headers to sheet if none exist
            if not existing_headers:
                print("📋 No existing headers found, will create new headers after first PDF")
            
            for i, file in enumerate(pdf_files, 1):
                try:
                    print(f"\n📄 Processing PDF {i}/{len(pdf_files)}: {file['name']}")
                    print(f"📊 Progress: {i}/{len(pdf_files)} files processed")
                    logger.info(f"[LLAMA] Processing PDF {i}/{len(pdf_files)}: {file['name']}")
                    
                    # Download PDF from Drive
                    pdf_data = self.download_from_drive(file['id'], file['name'])
                    
                    if not pdf_data:
                        print(f"❌ Failed to download PDF: {file['name']}")
                        logger.error(f"[ERROR] Failed to download PDF: {file['name']}")
                        stats['failed_pdfs'] += 1
                        continue
                    
                    # Save to temporary file for processing
                    temp_path = f"temp_{file['name']}"
                    with open(temp_path, "wb") as f:
                        f.write(pdf_data)
                    
                    # Extract data with LlamaParse
                    result = self.safe_extract(agent, temp_path)
                    extracted_data = result.data
                    
                    # Clean up temp file
                    os.remove(temp_path)
                    
                    # Flatten data for Google Sheets
                    rows = self.flatten_json(extracted_data)
                    for r in rows:
                        r["source_file"] = file['name']
                        r["processed_date"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        r["drive_file_id"] = file['id']
                    
                    if rows:
                        # Prepare data for Google Sheets
                        print(f"📊 Preparing {len(rows)} rows for Google Sheets...")
                        
                        # Get all unique keys to create comprehensive headers
                        all_keys = set()
                        for row in rows:
                            all_keys.update(row.keys())
                        
                        # Use existing headers if available, otherwise create new ones
                        if existing_headers:
                            headers = existing_headers
                            # Add any missing headers
                            for key in all_keys:
                                if key not in headers:
                                    headers.append(key)
                        else:
                            headers = list(all_keys)
                        
                        # Convert to list of lists for Sheets API
                        values = []
                        if not existing_headers:  # First run - include headers
                            values.append(headers)
                            existing_headers = headers  # Update headers for next iteration
                        
                        for row in rows:
                            row_values = [row.get(h, "") for h in headers]
                            values.append(row_values)
                        
                        # Append to Google Sheet
                        print(f"💾 Saving {len(rows)} rows from {file['name']} to Google Sheets...")
                        success = self.append_to_google_sheet(spreadsheet_id, sheet_range, values)
                        
                        if success:
                            stats['rows_added'] += len(rows)
                            print(f"✅ Successfully appended {len(rows)} rows from {file['name']} to Google Sheet")
                            logger.info(f"[SHEETS] Successfully appended {len(rows)} rows from {file['name']}")
                        else:
                            print(f"❌ Failed to update Google Sheet for {file['name']}")
                            logger.error(f"[ERROR] Failed to update Google Sheet for {file['name']}")
                    
                    stats['processed_pdfs'] += 1
                    print(f"✅ Successfully processed: {file['name']}")
                    print(f"📈 Extracted {len(rows)} rows from this PDF")
                    logger.info(f"[LLAMA] Successfully processed: {file['name']}")
                    
                except Exception as e:
                    print(f"❌ Error processing {file['name']}: {e}")
                    logger.error(f"[ERROR] Failed to process PDF {file['name']}: {str(e)}")
                    stats['failed_pdfs'] += 1
            
            return stats
            
        except Exception as e:
            print(f"❌ Unexpected error: {e}")
            logger.error(f"[ERROR] LlamaParse processing failed: {str(e)}")
            return stats

def main():
    """Run the PDF processing from Google Drive to Google Sheets"""
    
    print("=== Google Drive PDF Processor with LlamaParse ===")
    print("Processing PDFs from Google Drive and saving to Google Sheets")
    print()
    
    # Configuration - MODIFY THESE VALUES
    CONFIG = {
        'credentials_path': 'C:\\Users\\Lucifer\\Desktop\\New folder\\TBD\\GRN\\MoreRetail Automation\\credentials.json',
        'drive_folder_id': '1XHIFX-Gsb_Mx_AYjoi2NG1vMlvNE5CmQ',  # Google Drive folder with PDFs
        'llama_api_key': 'llx-DkwQuIwq5RVZk247W0r5WCdywejPI5CybuTDJgAUUcZKNq0A',
        'llama_agent': 'More retail Agent',
        'spreadsheet_id': '16y9DAK2tVHgnZNnPeRoSSPPE2NcspW_qqMF8ZR8OOC0',
        'sheet_range': 'mraws',
        'days_back': 1  # Add this: 1 for today, 2 for today + yesterday, etc. Set to None for all files
    }
    
    # Validate configuration
    if not os.path.exists(CONFIG['credentials_path']):
        print(f"[ERROR] Credentials file not found: {CONFIG['credentials_path']}")
        print()
        print("SETUP INSTRUCTIONS:")
        print("1. Go to https://console.cloud.google.com")
        print("2. Create a new project or select existing one")
        print("3. Enable Google Drive API and Google Sheets API")
        print("4. Go to 'Credentials' > 'Create Credentials' > 'OAuth client ID'")
        print("5. Choose 'Desktop application' as application type")
        print("6. Download the JSON file and save it as 'credentials.json'")
        print()
        print("Required packages:")
        print("pip install google-auth google-auth-oauthlib google-auth-httplib2 google-api-python-client")
        print("pip install llama-cloud-services")
        return
    
    # Initialize processor
    processor = DrivePDFProcessor(
        credentials_path=CONFIG['credentials_path']
    )
    
    # Authenticate
    print("🔐 Authenticating with Google APIs...")
    if not processor.authenticate():
        print("❌ Authentication failed")
        return
    
    # Process PDFs
    print("🚀 Starting PDF processing...")
    stats = processor.process_pdfs(
        drive_folder_id=CONFIG['drive_folder_id'],
        api_key=CONFIG['llama_api_key'],
        agent_name=CONFIG['llama_agent'],
        spreadsheet_id=CONFIG['spreadsheet_id'],
        sheet_range=CONFIG['sheet_range'],
        days_back=CONFIG['days_back']
    )
    
    # Print final results
    print("\n" + "="*50)
    print("📊 PROCESSING COMPLETE - FINAL STATISTICS")
    print("="*50)
    print(f"Total PDFs found: {stats['total_pdfs']}")
    print(f"Successfully processed: {stats['processed_pdfs']}")
    print(f"Failed to process: {stats['failed_pdfs']}")
    print(f"Rows added to Google Sheets: {stats['rows_added']}")
    print("="*50)
    
    if stats['failed_pdfs'] > 0:
        print("❌ Some PDFs failed to process. Check the log file for details.")
    elif stats['processed_pdfs'] > 0:
        print("✅ All PDFs processed successfully!")
    else:
        print("ℹ️ No PDFs were processed.")

if __name__ == "__main__":
    main()