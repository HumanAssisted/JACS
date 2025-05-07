from fastapi import FastAPI, Request, Response, Depends, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.responses import JSONResponse
import jacs
import os
from typing import Any
from pathlib import Path
import json
from starlette.types import Message

# Load JACS configuration
current_dir = Path(__file__).parent.absolute()
jacs_config_path = current_dir / "jacs.server.config.json"

# Set password if needed
os.environ["JACS_PRIVATE_KEY_PASSWORD"] = "hello"  # You should use a secure method in production

# Initialize JACS
jacs.load(str(jacs_config_path))

app = FastAPI()


# Middleware to verify incoming request bodies
class JacsRequestMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Only process requests with bodies
        if request.method in ["POST", "PUT", "PATCH"]:
            try:
                # Read request body
                body = await request.body()
                jacs_document = body.decode('utf-8')
                
                # Skip verification if body is empty
                if not jacs_document:
                    return await call_next(request)
                
                # Verify the signed request
                payload = jacs.verify_response(jacs_document)
                
                # Create a new receive function that returns the verified payload
                payload_bytes = json.dumps(payload).encode('utf-8')
                
                async def receive() -> Message:
                    return {
                        "type": "http.request",
                        "body": payload_bytes,
                        "more_body": False
                    }

                # Replace the request's receive function
                request._receive = receive
                
            except Exception as e:
                return JSONResponse(
                    status_code=400,
                    content={"error": f"Invalid JACS signature: {str(e)}"}
                )
        
        return await call_next(request)

# Dependency to access verified payload
async def get_verified_payload(request: Request):
    return request.state.verified_payload if hasattr(request.state, "verified_payload") else None

# Response signing function
def sign_response(data: Any) -> str:
    return jacs.sign_request(data)

# Custom response class for signing
class JacsJSONResponse(JSONResponse):
    def render(self, content: Any) -> bytes:
        # Sign the content before rendering
        signed_content = jacs.sign_request(content)
        return signed_content.encode("utf-8")

# Add the middleware to the app
app.add_middleware(JacsRequestMiddleware)

# Example route using the verified payload
@app.post("/api/data")
async def process_data(payload = Depends(get_verified_payload)):
    if not payload:
        raise HTTPException(status_code=400, detail="No verified payload found")
    
    # Process the verified payload
    return JacsJSONResponse(content={"message": "Processed verified data", "data": payload})

# Example route with manual response signing
@app.get("/api/manual-sign")
async def manual_sign():
    data = {"message": "This response is manually signed"}
    return Response(
        content=sign_response(data),
        media_type="application/json"
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)





