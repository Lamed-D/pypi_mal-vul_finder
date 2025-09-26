#!/usr/bin/env python3
"""
Test connection to server
"""
import requests
import time

def test_server_connection():
    """Test if server is responding"""
    try:
        print("Testing server connection...")
        response = requests.get('http://127.0.0.1:8000/', timeout=5)
        print(f"Server response: {response.status_code}")
        
        if response.status_code == 200:
            print("✅ Server is running and responding")
            return True
        else:
            print("❌ Server returned unexpected status code")
            return False
            
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to server - is it running?")
        return False
    except requests.exceptions.Timeout:
        print("❌ Server connection timeout")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

if __name__ == "__main__":
    # Wait a bit for server to start
    print("Waiting for server to start...")
    time.sleep(3)
    
    if test_server_connection():
        print("\n🎉 Server is ready for testing!")
    else:
        print("\n💥 Server is not ready")
