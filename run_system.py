"""
Root launcher for Multi-Agent AI Cybersecurity Threat Detection & Response System.
Allows running the project CLI directly from workspace root:
  python run_system.py
  python run_system.py --benchmark
"""

import os
import sys

# Add project package directory to sys.path
PROJECT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cybersecurity_multi_agent")
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import webbrowser
from dashboard.server import run_server
from run_system import main

if __name__ == "__main__":
    if "--ui" in sys.argv or "--dashboard" in sys.argv:
        port = 8000
        print(f"[*] Launching Multi-Agent SOC Dashboard at http://localhost:{port}/ ...")
        try:
            webbrowser.open(f"http://localhost:{port}/")
        except Exception:
            pass
        run_server(port)
    else:
        main()

