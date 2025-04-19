# install uv

    # curl -LsSf https://astral.sh/uv/install.sh | sh
    # uv init jacs-mcp
    
    uv venv
 
    # uv add "mcp[cli]" --active
    

    
    source .venv/bin/activate
    uv sync
    mcp run main.py

or
    source .venv/bin/activate
    mcp run client.py