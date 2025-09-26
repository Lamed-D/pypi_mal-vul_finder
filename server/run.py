"""
Main entry point for the Python Security Analysis System
"""
import uvicorn
import os
import sys
from pathlib import Path

# Add the server directory to Python path
server_dir = Path(__file__).parent
sys.path.insert(0, str(server_dir))

from config import HOST, PORT, LOG_LEVEL
from database.database import init_database

def main():
    """Start the security analysis server"""
    print("=" * 60)
    print("Python Security Analysis System")
    print("=" * 60)
    print(f"Server starting on http://{HOST}:{PORT}")
    print(f"Log level: {LOG_LEVEL}")
    print("=" * 60)
    
    # Initialize database
    print("Initializing database...")
    init_database()
    print("Database initialized successfully")
    
    # Start server
    uvicorn.run(
        "app.main:app",
        host=HOST,
        port=PORT,
        log_level=LOG_LEVEL.lower(),
        reload=True
    )

if __name__ == "__main__":
    main()
