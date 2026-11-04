"""
Sanket (સંકેત / संकेत) — AI-Powered Cyber Threat Indicator & Safety Platform
Launcher script: starts FastAPI server and opens Web Dashboard in browser.
"""
import os
import sys
import threading
import time
import webbrowser

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import uvicorn

def open_browser():
    time.sleep(1.8)
    url = "http://localhost:8000"
    print(f"\n[SANKET] Opening browser dashboard at: {url}\n")
    webbrowser.open(url)

if __name__ == "__main__":
    print("=" * 75)
    print("SANKET (સંકેત / संकेत) — AI CYBER THREAT INDICATOR & RESPONSE PLATFORM")
    print("Major Project | Department of Data Science & Machine Learning")
    print("Navrachana University, Vadodara, Gujarat (2026-27)")
    print("Guide: Prof. Ujwala Patigara")
    print("Presented by: Isha Rajput, Parisha Parmar, Priya Bhatt")
    print("=" * 75)
    print("Starting FastAPI Server on http://localhost:8000 ...")

    # Launch browser in separate thread
    threading.Thread(target=open_browser, daemon=True).start()

    # Run Uvicorn server (host 0.0.0.0 makes it accessible to both laptop and phone on local WiFi!)
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=False)
