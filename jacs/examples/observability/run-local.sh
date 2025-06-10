#!/bin/bash

# Create directories
mkdir -p logs metrics

# Set environment variable to help with dependency resolution
export JACS_AGENT_KEY_ALGORITHM=RSA-PSS

echo "Starting JACS Observability Demo locally..."
echo "Logs will be written to: ./logs/"
echo "Metrics will be written to: ./metrics/"
echo "Health check available at: http://localhost:8080"
echo ""
echo "Press Ctrl+C to stop"

# Run the demo
cargo run