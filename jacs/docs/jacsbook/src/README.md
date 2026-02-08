# JACS: JSON Agent Communication Standard

Welcome to the **JSON Agent Communication Standard (JACS)** documentation! JACS is a comprehensive framework for creating, signing, and verifying JSON documents with cryptographic integrity, designed specifically for AI agent communication and task management.

## What is JACS?

JACS provides a standard way for AI agents to:
- **Create and sign** JSON documents with cryptographic signatures
- **Verify authenticity** and integrity of documents
- **Manage tasks and agreements** between multiple agents
- **Maintain audit trails** of modifications and versioning
- **Ensure trust** in multi-agent systems

As a developer, JACS gives you the tools to build trustworthy AI systems where agents can securely exchange tasks, agreements, and data with verifiable integrity.

## Key Features

- 🔐 **Cryptographic Security**: RSA, Ed25519, and post-quantum cryptographic algorithms
- 📋 **JSON Schema Validation**: Enforced document structure and validation
- 🤝 **Multi-Agent Agreements**: Built-in support for agent collaboration and task agreements
- 🔍 **Full Audit Trail**: Complete versioning and modification history
- 🌐 **Multiple Language Support**: Rust, Node.js, and Python implementations
- 🔌 **MCP Integration**: Native Model Context Protocol support
- 📊 **Observability**: Built-in logging and metrics for production systems

## Available Implementations

JACS is available in three languages, each with its own strengths:

### 🦀 Rust (Core Library + CLI)
- **Performance**: Fastest implementation with native performance
- **CLI Tool**: Complete command-line interface for agent and document management
- **Library**: Full-featured Rust library for embedded applications
- **Observability**: Advanced logging and metrics with OpenTelemetry support

### 🟢 Node.js (@hai-ai/jacs)
- **Web Integration**: Perfect for web servers and Express.js applications
- **MCP Support**: Native Model Context Protocol integration
- **HTTP Server**: Built-in HTTP server capabilities
- **NPM Package**: Easy installation and integration

### 🐍 Python (jacs)
- **AI/ML Integration**: Ideal for AI and machine learning workflows
- **MCP Support**: Authenticated MCP server patterns
- **PyPI Package**: Simple `pip install` integration
- **Data Science**: Perfect for Jupyter notebooks and data pipelines

## Quick Start

Choose your implementation and get started in minutes:

### Rust CLI
```bash
cargo install jacs
jacs init  # Create config, keys, and agent
```

Or step by step:
```bash
jacs config create
jacs agent create --create-keys true
```

### Node.js
```bash
npm install @hai-ai/jacs
```
```javascript
import { JacsAgent } from '@hai-ai/jacs';

const agent = new JacsAgent();
agent.load('./config.json');
```

### Python
```bash
pip install jacs
```
```python
import jacs

agent = jacs.JacsAgent()
agent.load("./config.json")
```

## When to Use JACS

JACS is ideal for scenarios where you need:

- **Multi-agent systems** where agents need to trust each other
- **Task delegation** with verifiable completion and approval
- **Audit trails** for AI decision-making processes  
- **Secure data exchange** between AI systems
- **Compliance** requirements for AI system interactions
- **Version control** for AI-generated content and decisions

## Why JACS?

### 🎯 **Agent-Focused Design**
Unlike general-purpose signing frameworks, JACS is specifically designed for AI agent communication patterns - tasks, agreements, and collaborative workflows.

### 🚀 **Production Ready**
With built-in observability, multiple storage backends, and comprehensive error handling, JACS is ready for production AI systems.

### 🔒 **Future-Proof Security**
Support for both current (RSA, Ed25519) and post-quantum cryptographic algorithms ensures your system remains secure.

### 🌐 **Universal Compatibility**
JSON-based documents work everywhere - store them in any database, transmit over any protocol, integrate with any system.

### 🧩 **Flexible Integration**
Whether you're building a simple CLI tool or a complex multi-agent system, JACS adapts to your architecture.

## Getting Started

1. **[Core Concepts](getting-started/concepts.md)** - Understand agents, documents, and agreements
2. **[Quick Start Guide](getting-started/quick-start.md)** - Get up and running in minutes
3. **Choose Your Implementation**:
   - [Rust CLI & Library](rust/installation.md)
   - [Node.js Package](nodejs/installation.md)
   - [Python Package](python/installation.md)

## Community and Support

- **GitHub**: [HumanAssisted/JACS](https://github.com/HumanAssisted/JACS)
- **Issues**: Report bugs and feature requests
- **Examples**: Complete examples for all implementations
- **Documentation**: This comprehensive guide

---

*Ready to build trustworthy AI systems? Let's get started!*
