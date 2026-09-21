#!/bin/bash
# Count lines of code for Rust, Go, TypeScript, TSX, and Python
# Excludes node_modules, build directories, and other temp/lib directories
# Uses --no-ignore to count all files, not just those tracked by git

tokei \
  --no-ignore \
  --exclude 'node_modules' \
  --exclude 'target' \
  --exclude 'dist' \
  --exclude 'build' \
  --exclude '__pycache__' \
  --exclude '.venv' \
  --exclude 'venv' \
  --exclude '.next' \
  --exclude '.turbo' \
  --exclude '*.lock' \
  --exclude 'Cargo.lock' \
  --types Rust,Go,TypeScript,TSX,Python \
> LINES_OF_CODE.md

cat LINES_OF_CODE.md
