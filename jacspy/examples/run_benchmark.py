#!/usr/bin/env python3
"""
HAI.ai Benchmark Runner Example

This example demonstrates how to run benchmarks via HAI.ai platform.

Prerequisites:
    1. Create and register a JACS agent:
       python quickstart.py --create
       python register_with_hai.py https://hai.ai --api-key YOUR_API_KEY

    2. Install HAI dependencies:
       pip install httpx httpx-sse

Usage:
    # Run the default "mediator" benchmark suite
    python run_benchmark.py https://hai.ai --api-key YOUR_API_KEY

    # Run a specific benchmark suite
    python run_benchmark.py https://hai.ai --api-key YOUR_API_KEY --suite security

    # Use environment variable for API key
    export HAI_API_KEY=your-api-key
    python run_benchmark.py https://hai.ai

Available Benchmark Suites:
    - mediator: Tests agent mediation capabilities
    - security: Tests cryptographic operations
    - performance: Tests throughput and latency
    - compliance: Tests JACS specification compliance
"""

import argparse
import json
import os
import sys
import time

# Add parent directory for development imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))

import jacs.simple as jacs
from jacs.hai import (
    HaiClient,
    HaiError,
    BenchmarkError,
    HaiConnectionError,
    AuthenticationError,
    BenchmarkResult,
)


def format_duration(ms: int) -> str:
    """Format milliseconds as human-readable duration."""
    if ms < 1000:
        return f"{ms}ms"
    elif ms < 60000:
        return f"{ms / 1000:.1f}s"
    else:
        minutes = ms // 60000
        seconds = (ms % 60000) / 1000
        return f"{minutes}m {seconds:.0f}s"


def print_result_details(results: list):
    """Print detailed test results."""
    for i, result in enumerate(results, 1):
        status = "PASS" if result.get("passed", result.get("success", False)) else "FAIL"
        name = result.get("name", result.get("test", f"Test {i}"))
        duration = result.get("duration_ms", result.get("durationMs", 0))

        print(f"  [{status}] {name} ({duration}ms)")

        if not result.get("passed", result.get("success", True)):
            error = result.get("error", result.get("message", ""))
            if error:
                print(f"        Error: {error}")


def run_benchmark(hai_url: str, api_key: str, suite: str, timeout: float = 300.0) -> BenchmarkResult:
    """Run a benchmark suite and return results."""
    print(f"\nStarting benchmark suite: {suite}")
    print("-" * 40)

    hai = HaiClient(timeout=timeout)

    start_time = time.time()

    try:
        result = hai.benchmark(
            hai_url=hai_url,
            api_key=api_key,
            suite=suite,
            timeout=timeout,
        )

        elapsed = time.time() - start_time
        print(f"\nBenchmark completed in {elapsed:.1f}s")

        return result

    except AuthenticationError as e:
        print(f"\nAuthentication failed: {e}")
        print("  Check your API key and permissions.")
        sys.exit(1)

    except BenchmarkError as e:
        print(f"\nBenchmark failed: {e}")
        if e.response_data:
            print(f"  Details: {json.dumps(e.response_data, indent=2)}")
        sys.exit(1)

    except HaiConnectionError as e:
        print(f"\nConnection error: {e}")
        print("  Check your network and the HAI.ai URL.")
        sys.exit(1)

    except HaiError as e:
        print(f"\nError: {e}")
        sys.exit(1)


def print_benchmark_summary(result: BenchmarkResult):
    """Print a summary of benchmark results."""
    print("\n" + "=" * 60)
    print("BENCHMARK RESULTS")
    print("=" * 60)

    # Score with visual indicator
    score = result.score
    if score >= 90:
        grade = "Excellent"
    elif score >= 75:
        grade = "Good"
    elif score >= 60:
        grade = "Fair"
    else:
        grade = "Needs Improvement"

    print(f"\nSuite: {result.suite}")
    print(f"Score: {score:.1f}/100 ({grade})")
    print(f"Tests: {result.passed}/{result.total} passed, {result.failed} failed")
    print(f"Duration: {format_duration(result.duration_ms)}")

    # Visual score bar
    bar_width = 40
    filled = int(score / 100 * bar_width)
    bar = "#" * filled + "-" * (bar_width - filled)
    print(f"\n[{bar}] {score:.1f}%")

    # Detailed results if available
    if result.results:
        print("\nDetailed Results:")
        print_result_details(result.results)


def main():
    parser = argparse.ArgumentParser(
        description="Run HAI.ai benchmarks for a JACS agent",
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
        "--suite", "-s",
        default="mediator",
        help="Benchmark suite to run (default: mediator)",
    )
    parser.add_argument(
        "--config", "-c",
        default="./jacs.config.json",
        help="Path to JACS config file (default: ./jacs.config.json)",
    )
    parser.add_argument(
        "--timeout", "-t",
        type=float,
        default=300.0,
        help="Benchmark timeout in seconds (default: 300)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON",
    )

    args = parser.parse_args()

    # Get API key
    api_key = args.api_key or os.environ.get("HAI_API_KEY")
    if not api_key:
        print("Error: API key required")
        print("  Set HAI_API_KEY environment variable or use --api-key")
        sys.exit(1)

    if not args.json:
        print("=" * 60)
        print("HAI.ai Benchmark Runner")
        print("=" * 60)

    # Load JACS agent
    if not args.json:
        print(f"\nLoading JACS agent from {args.config}...")

    try:
        agent_info = jacs.load(args.config)
        if not args.json:
            print(f"  Agent ID: {agent_info.agent_id}")
    except jacs.ConfigError as e:
        if args.json:
            print(json.dumps({"error": str(e)}))
        else:
            print(f"\nError: {e}")
            print("\nCreate an agent first with:")
            print("  python quickstart.py --create")
        sys.exit(1)

    # Run benchmark
    result = run_benchmark(
        hai_url=args.hai_url,
        api_key=api_key,
        suite=args.suite,
        timeout=args.timeout,
    )

    # Output results
    if args.json:
        output = {
            "success": result.success,
            "suite": result.suite,
            "score": result.score,
            "passed": result.passed,
            "failed": result.failed,
            "total": result.total,
            "duration_ms": result.duration_ms,
            "results": result.results,
        }
        print(json.dumps(output, indent=2))
    else:
        print_benchmark_summary(result)

        print("\n" + "=" * 60)
        if result.success and result.score >= 75:
            print("Benchmark completed successfully!")
        else:
            print("Benchmark completed with issues. Review results above.")
        print("=" * 60)

    # Exit with appropriate code
    sys.exit(0 if result.success else 1)


if __name__ == "__main__":
    main()
