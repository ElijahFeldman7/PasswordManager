from googleapiclient.http import MediaFileUpload, MediaIoBaseDownload
import io

VAULT_FILENAME = 'vault.dat'

def find_remote_vault(service):
    """Searches for the vault file in Drive and returns its ID and modified time."""
    response = service.files().list(
        q=f"name='{VAULT_FILENAME}'",
        spaces='drive',
        fields='files(id, modifiedTime)'
    ).execute()
    files = response.get('files', [])
    if not files:
        return None, None
    return files[0]['id'], files[0]['modifiedTime']

def download_vault(service, file_id, local_path):
    """Downloads the vault file from Drive."""
    request = service.files().get_media(fileId=file_id)
    fh = io.BytesIO()
    downloader = MediaIoBaseDownload(fh, request)
    done = False
    while not done:
        status, done = downloader.next_chunk()

    with open(local_path, 'wb') as f:
        f.write(fh.getvalue())
    print("Vault downloaded from cloud.")

def upload_vault(service, local_path):
    """Uploads the local vault file, creating or overwriting as needed."""
    file_id, _ = find_remote_vault(service)
    
    media = MediaFileUpload(local_path, mimetype='application/octet-stream')

    if file_id:
        service.files().update(fileId=file_id, media_body=media).execute()
        print("Remote vault updated.")
    else:
        file_metadata = {'name': VAULT_FILENAME}
        service.files().create(body=file_metadata, media_body=media).execute()
        print("Remote vault created.")