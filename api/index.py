"""
Vercel Serverless Function Entry Point for Nirbhay Platform
Mounts the FastAPI application for serverless execution.
"""
import os
import sys

# Ensure repository root is on sys.path
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from backend.main import app

