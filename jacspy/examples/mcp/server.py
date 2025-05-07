from fastapi import FastAPI, Request, Response, Depends, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.responses import JSONResponse
import jacs
import os
from typing import Any
from pathlib import Path
import json
import logging
from starlette.types import Message

logger = logging.getLogger(__name__)
# Load JACS configuration
current_dir = Path(__file__).parent.absolute()
jacs_config_path = current_dir / "jacs.server.config.json"

# Set password if needed
os.environ["JACS_PRIVATE_KEY_PASSWORD"] = "hello"  # You should use a secure method in production

# Initialize JACS
jacs.load(str(jacs_config_path))
 