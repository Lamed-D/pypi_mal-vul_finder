#!/usr/bin/env python3
"""
Simple upload test
"""
import requests
import os
import zipfile
import tempfile
import time

def create_test_zip():
    """Create a simple test ZIP file"""
    with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as tmp:
        with zipfile.ZipFile(tmp.name, 'w') as zipf:
            zipf.writestr('test.py', 'print("Hello, World!")')
            zipf.writestr('requirements.txt', 'requests==2.28.0')
        return tmp.name

def test_upload():
    """Test the upload endpoint"""
    try:
        print("Creating test ZIP file...")
        zip_path = create_test_zip()
        print(f"Created test ZIP: {zip_path}")
        
        print("Waiting for server to start...")
        time.sleep(5)
        
        print("Testing upload...")
        with open(zip_path, 'rb') as f:
            files = {'file': ('test.zip', f, 'application/zip')}
            response = requests.post('http://127.0.0.1:8000/upload', files=files)
        
        print(f"Response status: {response.status_code}")
        print(f"Response content: {response.text}")
        
        if response.status_code == 200:
            print("✅ Upload successful!")
        else:
            print("❌ Upload failed!")
        
        # Clean up
        os.unlink(zip_path)
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_upload()
