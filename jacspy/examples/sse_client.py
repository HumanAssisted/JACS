#!/usr/bin/env python3
"""
HAI.ai SSE Client Example

This example demonstrates how to connect to HAI.ai's Server-Sent Events
stream to receive real-time events like jobs, messages, and heartbeats.

Prerequisites:
    1. Register a JACS agent with HAI.ai:
       python register_with_hai.py https://hai.ai --api-key YOUR_API_KEY

    2. Install HAI dependencies:
       pip install httpx httpx-sse

Usage:
    # Connect and listen for events
    python sse_client.py https://hai.ai --api-key YOUR_API_KEY

    # With timeout (auto-disconnect after N seconds)
    python sse_client.py https://hai.ai --api-key YOUR_API_KEY --timeout 60

Event Types:
    - heartbeat: Periodic keepalive signal
    - job: New benchmark or task job
    - message: General message from HAI.ai
    - result: Result of a completed operation
"""

import argparse
import json
import os
import signal
import sys
import threading
import time
from datetime import datetime

# Add parent directory for development imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))

import jacs.simple as jacs
from jacs.hai import (
    HaiClient,
    HaiEvent,
    HaiError,
    HaiConnectionError,
    AuthenticationError,
    SSEError,
)


class EventHandler:
    """Handler for SSE events from HAI.ai."""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.event_count = 0
        self.start_time = time.time()

    def handle_event(self, event: HaiEvent):
        """Process an incoming event."""
        self.event_count += 1
        timestamp = datetime.now().strftime("%H:%M:%S")

        if event.event_type == "heartbeat":
            if self.verbose:
                print(f"[{timestamp}] Heartbeat received")
            else:
                # Just print a dot for heartbeats
                print(".", end="", flush=True)

        elif event.event_type == "job":
            print(f"\n[{timestamp}] JOB RECEIVED")
            self._print_job(event.data)

        elif event.event_type == "message":
            print(f"\n[{timestamp}] MESSAGE: {event.data}")

        elif event.event_type == "result":
            print(f"\n[{timestamp}] RESULT:")
            if isinstance(event.data, dict):
                print(json.dumps(event.data, indent=2))
            else:
                print(f"  {event.data}")

        else:
            print(f"\n[{timestamp}] {event.event_type.upper()}: {event.data}")

    def _print_job(self, job_data):
        """Pretty print a job."""
        if isinstance(job_data, dict):
            job_id = job_data.get("job_id", job_data.get("jobId", "unknown"))
            job_type = job_data.get("type", job_data.get("jobType", "unknown"))
            print(f"  Job ID: {job_id}")
            print(f"  Type: {job_type}")

            if "payload" in job_data:
                print(f"  Payload: {json.dumps(job_data['payload'], indent=4)}")
        else:
            print(f"  {job_data}")

    def stats(self):
        """Print event statistics."""
        elapsed = time.time() - self.start_time
        rate = self.event_count / elapsed if elapsed > 0 else 0
        print(f"\n\nReceived {self.event_count} events in {elapsed:.1f}s ({rate:.2f}/s)")


def main():
    parser = argparse.ArgumentParser(
        description="Connect to HAI.ai SSE event stream",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "hai_url",
        nargs="?",
        default="https://hai.ai",
        help="HAI.ai server URL (default: https://hai.ai)",
    )
    parser.add_argument(
        "--api-key", "-k",
        help="HAI.ai API key (required, or set HAI_API_KEY env var)",
    )
    parser.add_argument(
        "--config", "-c",
        default="./jacs.config.json",
        help="Path to JACS config file (default: ./jacs.config.json)",
    )
    parser.add_argument(
        "--timeout", "-t",
        type=float,
        help="Auto-disconnect after N seconds (default: run forever)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show all events including heartbeats",
    )

    args = parser.parse_args()

    # Get API key
    api_key = args.api_key or os.environ.get("HAI_API_KEY")
    if not api_key:
        print("Error: API key required")
        print("  Set HAI_API_KEY environment variable or use --api-key")
        sys.exit(1)

    print("=" * 60)
    print("HAI.ai SSE Client")
    print("=" * 60)

    # Load JACS agent
    print(f"\nLoading JACS agent from {args.config}...")
    try:
        agent_info = jacs.load(args.config)
        print(f"  Agent ID: {agent_info.agent_id}")
    except jacs.ConfigError as e:
        print(f"\nError: {e}")
        sys.exit(1)

    # Create client and handler
    hai = HaiClient()
    handler = EventHandler(verbose=args.verbose)

    # Set up graceful shutdown
    shutdown_event = threading.Event()

    def signal_handler(signum, frame):
        print("\n\nShutting down...")
        shutdown_event.set()
        hai.disconnect()

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Start timeout timer if specified
    if args.timeout:
        def timeout_disconnect():
            shutdown_event.wait(args.timeout)
            if not shutdown_event.is_set():
                print(f"\n\nTimeout after {args.timeout}s")
                hai.disconnect()

        timer_thread = threading.Thread(target=timeout_disconnect, daemon=True)
        timer_thread.start()

    # Connect and process events
    print(f"\nConnecting to {args.hai_url}...")
    print("Press Ctrl+C to disconnect\n")

    try:
        for event in hai.connect(args.hai_url, api_key, on_event=handler.handle_event):
            if shutdown_event.is_set():
                break

    except AuthenticationError as e:
        print(f"\nAuthentication failed: {e}")
        sys.exit(1)

    except HaiConnectionError as e:
        print(f"\nConnection error: {e}")
        sys.exit(1)

    except SSEError as e:
        print(f"\nSSE error: {e}")
        sys.exit(1)

    except HaiError as e:
        print(f"\nError: {e}")
        sys.exit(1)

    finally:
        handler.stats()
        print("\nDisconnected.")


if __name__ == "__main__":
    main()
