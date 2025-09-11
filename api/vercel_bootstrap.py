"""
Vercel Bootstrap File

This file is used by Vercel (a cloud platform for deploying web applications)
to properly load and run the FastAPI application.

Vercel uses this file to:
1. Import the FastAPI application instance
2. Make the app available for deployment
3. Handle the serverless function execution

The 'app' variable imported here is the main FastAPI application
defined in main.py, which contains all the API endpoints and logic.

For Vercel deployment, this file must be in the 'api' directory
and must export the FastAPI app instance.
"""

# Import the main FastAPI application from the main.py file
from main import app
