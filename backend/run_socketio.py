"""
Usage (Windows PowerShell):
  $env:SOCKETIO_ENABLED="true"
  python -m backend.run_socketio
"""

from backend.app import create_app
from backend.extensions import socketio

def main():
    app = create_app()
    socketio.run(app, host="127.0.0.1", port=5000, debug=True, use_reloader=False)

if __name__ == "__main__":
    main()
