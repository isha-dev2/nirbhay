#!/usr/bin/env python3
"""
run_app.py — Nirbhay Application Launcher
Starts FastAPI backend on port 8000 and automatically opens the Web Dashboard.
"""
import os
import sys
import threading
import time
import webbrowser
import uvicorn

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

def open_browser():
    time.sleep(1.5)
    url = "http://localhost:8000"
    print(f"\n[NIRBHAY] Opening Web Dashboard: {url}\n")
    webbrowser.open(url)

if __name__ == "__main__":
    print("=" * 72)
    print("🛡️  NIRBHAY (निर्भय • નિર્ભય) — AI Digital Safety & Response Platform")
    print("   Major Project 2026-27 | Dept of Data Science & Machine Learning")
    print("   Navrachana University, Vadodara, Gujarat")
    print("   Guide: Prof. Ujwala Patigara")
    print("   Team: Isha Rajput, Priya Bhatt, Parisha Parmar")
    print("=" * 72)
    print("Starting server on http://localhost:8000 ...")

    threading.Thread(target=open_browser, daemon=True).start()
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=False)

