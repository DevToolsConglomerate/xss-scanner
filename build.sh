#!/bin/bash
# Vercel Build Script for Python (FastAPI) project
echo "Installing Python dependencies from requirements.txt..."
pip install -r requirements.txt -t .vercel/packages/python/lib/python3.11/site-packages
echo "Build complete."