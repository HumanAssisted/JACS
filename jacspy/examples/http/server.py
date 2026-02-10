"""FastAPI server with automatic JACS signing via JacsMiddleware.

Signs all JSON responses and verifies incoming signed requests.

    pip install jacs[fastapi] uvicorn

    python server.py
"""

from fastapi import FastAPI
from jacs.adapters.fastapi import JacsMiddleware, jacs_route
from jacs.client import JacsClient

# Create a JACS client (auto-creates keys if none exist)
client = JacsClient.quickstart()

app = FastAPI(title="JACS Signed API")

# Option 1: Middleware signs ALL JSON responses automatically
app.add_middleware(JacsMiddleware, client=client)


@app.post("/api/data")
async def process_data(payload: dict):
    """Receives data, returns signed response."""
    return {"message": "Processed", "data": payload}


@app.get("/api/status")
async def status():
    return {"status": "ok", "agent_id": client.agent_id}


# Option 2: Per-route signing (use instead of or alongside middleware)
@app.get("/api/signed-only")
@jacs_route(client=client)
async def signed_endpoint():
    return {"result": "this response is individually signed"}


if __name__ == "__main__":
    import uvicorn

    print(f"Starting JACS-signed FastAPI server (agent: {client.agent_id})")
    uvicorn.run(app, host="0.0.0.0", port=8000)
