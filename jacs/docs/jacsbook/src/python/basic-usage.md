# Basic Usage

This guide covers the fundamental operations you can perform with JACS in Python, from creating agents to managing tasks and documents.

## Quick Start Example

Here's a complete example that demonstrates the core JACS workflow:

```python
import jacs
import json
import os

# Configuration
config = {
    "jacs_data_directory": "./jacs_data",
    "jacs_key_directory": "./jacs_keys",
    "jacs_default_storage": "fs",
    "jacs_agent_key_algorithm": "Ed25519"
}

# Ensure directories exist
os.makedirs(config["jacs_data_directory"], exist_ok=True)
os.makedirs(config["jacs_key_directory"], exist_ok=True)

# Create agent
agent = jacs.Agent(config)

# Generate keys and create agent document
agent.generate_keys()
agent_doc = agent.create_agent({
    "name": "My Python Agent",
    "description": "A JACS agent for Python workflows",
    "type": "automation"
})

print(f"Created agent: {agent_doc['name']}")
print(f"Agent ID: {agent_doc['jacsId']}")

# Create a task
task_doc = agent.create_task({
    "title": "Process Data",
    "description": "Analyze customer data and generate report",
    "priority": "high",
    "status": "pending"
})

print(f"Created task: {task_doc['title']}")
print(f"Task ID: {task_doc['jacsId']}")

# Update task status
updated_task = agent.update_task(task_doc['jacsId'], {
    "status": "in_progress",
    "progress": 25
})

print(f"Updated task status: {updated_task['status']}")
```

## Agent Management

### Creating an Agent

```python
import jacs

# Basic agent creation
config = {
    "jacs_data_directory": "./jacs_data",
    "jacs_key_directory": "./jacs_keys",
    "jacs_default_storage": "fs",
    "jacs_agent_key_algorithm": "Ed25519"
}

agent = jacs.Agent(config)

# Generate cryptographic keys
agent.generate_keys()

# Create agent document
agent_doc = agent.create_agent({
    "name": "Data Processor",
    "description": "Agent specialized in data processing tasks",
    "type": "data_processor",
    "capabilities": ["data_analysis", "report_generation"],
    "version": "1.0.0"
})

print(f"Agent created with ID: {agent_doc['jacsId']}")
```

### Loading an Existing Agent

```python
# If you have an existing agent, specify it in config
config = {
    "jacs_data_directory": "./jacs_data",
    "jacs_key_directory": "./jacs_keys",
    "jacs_default_storage": "fs",
    "jacs_agent_key_algorithm": "Ed25519",
    "jacs_agent_id_and_version": "agent_123:1"  # Load existing agent
}

agent = jacs.Agent(config)

# Agent is now loaded and ready to use
print("Existing agent loaded successfully")
```

### Agent Information

```python
# Get agent information
agent_info = agent.get_agent_info()
print(f"Agent Name: {agent_info['name']}")
print(f"Agent Type: {agent_info['type']}")
print(f"Capabilities: {agent_info.get('capabilities', [])}")
```

## Task Management

### Creating Tasks

```python
# Simple task
task = agent.create_task({
    "title": "Data Analysis",
    "description": "Analyze sales data for Q4",
    "status": "pending"
})

# Detailed task with metadata
detailed_task = agent.create_task({
    "title": "Generate Monthly Report",
    "description": "Create comprehensive monthly performance report",
    "priority": "high",
    "status": "pending",
    "assignee": "data_team",
    "due_date": "2024-02-01",
    "tags": ["reporting", "monthly", "performance"],
    "metadata": {
        "department": "analytics",
        "report_type": "performance",
        "data_sources": ["sales", "marketing", "support"]
    }
})

print(f"Created task: {detailed_task['jacsId']}")
```

### Updating Tasks

```python
# Update task status
updated_task = agent.update_task(task['jacsId'], {
    "status": "in_progress",
    "progress": 50,
    "notes": "Data collection completed, starting analysis"
})

# Add results to completed task
completed_task = agent.update_task(task['jacsId'], {
    "status": "completed",
    "progress": 100,
    "results": {
        "total_sales": 1250000,
        "growth_rate": 15.3,
        "top_products": ["Product A", "Product B", "Product C"]
    },
    "completion_date": "2024-01-15"
})
```

### Querying Tasks

```python
# Get all tasks
all_tasks = agent.list_tasks()
print(f"Total tasks: {len(all_tasks)}")

# Filter tasks by status
pending_tasks = [task for task in all_tasks if task.get('status') == 'pending']
print(f"Pending tasks: {len(pending_tasks)}")

# Get specific task
task_details = agent.get_task(task['jacsId'])
print(f"Task: {task_details['title']}")
```

## Document Management

### Creating Documents

```python
# Create a generic document
document = agent.create_document({
    "type": "report",
    "title": "Q4 Sales Analysis",
    "content": {
        "summary": "Sales increased by 15% in Q4",
        "details": {
            "total_revenue": 1250000,
            "units_sold": 5000,
            "average_order_value": 250
        }
    },
    "author": "analytics_team",
    "created_date": "2024-01-15"
})

print(f"Document created: {document['jacsId']}")
```

### Document Versioning

```python
# Update document (creates new version)
updated_document = agent.update_document(document['jacsId'], {
    "content": {
        "summary": "Sales increased by 15.3% in Q4 (revised)",
        "details": {
            "total_revenue": 1253000,  # Corrected figure
            "units_sold": 5012,
            "average_order_value": 250.1
        }
    },
    "revision_notes": "Corrected revenue figures"
})

print(f"Document updated to version: {updated_document['jacsVersion']}")
```

### Document Verification

```python
# Verify document signature
is_valid = agent.verify_document(document['jacsId'])
print(f"Document signature valid: {is_valid}")

# Get document history
history = agent.get_document_history(document['jacsId'])
print(f"Document has {len(history)} versions")
```

## Agreement Management

### Creating Agreements

```python
# Create a multi-party agreement
agreement = agent.create_agreement({
    "title": "Data Sharing Agreement",
    "description": "Agreement for sharing customer data between departments",
    "parties": ["analytics_team", "marketing_team", "legal_team"],
    "terms": {
        "data_types": ["customer_demographics", "purchase_history"],
        "usage_restrictions": ["no_external_sharing", "anonymization_required"],
        "duration": "12_months"
    },
    "status": "draft"
})

print(f"Agreement created: {agreement['jacsId']}")
```

### Agreement Workflow

```python
# Submit agreement for approval
submitted_agreement = agent.update_agreement(agreement['jacsId'], {
    "status": "pending_approval",
    "submitted_by": "analytics_team",
    "submitted_date": "2024-01-15"
})

# Approve agreement (would be done by each party)
approved_agreement = agent.approve_agreement(agreement['jacsId'], {
    "approver": "legal_team",
    "approval_date": "2024-01-16",
    "notes": "Approved with standard terms"
})

# Finalize agreement
final_agreement = agent.finalize_agreement(agreement['jacsId'])
print(f"Agreement status: {final_agreement['status']}")
```

## Working with JSON Schemas

### Schema Validation

```python
# Define a custom schema for your documents
task_schema = {
    "type": "object",
    "properties": {
        "title": {"type": "string", "minLength": 1},
        "description": {"type": "string"},
        "priority": {"type": "string", "enum": ["low", "medium", "high"]},
        "status": {"type": "string", "enum": ["pending", "in_progress", "completed"]},
        "assignee": {"type": "string"},
        "due_date": {"type": "string", "format": "date"}
    },
    "required": ["title", "description", "status"]
}

# Create task with schema validation
try:
    validated_task = agent.create_task({
        "title": "Validated Task",
        "description": "This task follows the schema",
        "priority": "high",
        "status": "pending",
        "assignee": "john_doe",
        "due_date": "2024-02-01"
    }, schema=task_schema)
    print("Task created and validated successfully")
except Exception as e:
    print(f"Schema validation failed: {e}")
```

## Error Handling

### Common Error Patterns

```python
import jacs

try:
    agent = jacs.Agent(config)
    
    # Attempt to create agent
    agent.generate_keys()
    agent_doc = agent.create_agent({
        "name": "Test Agent",
        "description": "Testing error handling"
    })
    
except jacs.ConfigurationError as e:
    print(f"Configuration error: {e}")
    # Handle configuration issues
    
except jacs.CryptographicError as e:
    print(f"Cryptographic error: {e}")
    # Handle key generation or signing issues
    
except jacs.ValidationError as e:
    print(f"Validation error: {e}")
    # Handle schema validation failures
    
except jacs.StorageError as e:
    print(f"Storage error: {e}")
    # Handle file system or cloud storage issues
    
except Exception as e:
    print(f"Unexpected error: {e}")
    # Handle any other errors
```

### Robust Error Handling

```python
def create_agent_safely(config):
    """Create agent with comprehensive error handling"""
    try:
        agent = jacs.Agent(config)
        
        # Check if keys exist
        if not agent.has_keys():
            print("Generating new keys...")
            agent.generate_keys()
        
        # Check if agent document exists
        if not config.get("jacs_agent_id_and_version"):
            print("Creating new agent...")
            agent_doc = agent.create_agent({
                "name": "Robust Agent",
                "description": "Agent with error handling"
            })
            return agent, agent_doc
        else:
            print("Loading existing agent...")
            return agent, None
            
    except Exception as e:
        print(f"Failed to create agent: {e}")
        return None, None

# Usage
agent, agent_doc = create_agent_safely(config)
if agent:
    print("Agent ready for use")
else:
    print("Failed to initialize agent")
```

## Configuration Management

### Environment-Based Configuration

```python
import os
import json

def load_config():
    """Load configuration from environment or file"""
    
    # Try environment variables first
    if os.getenv("JACS_DATA_DIRECTORY"):
        return {
            "jacs_data_directory": os.getenv("JACS_DATA_DIRECTORY"),
            "jacs_key_directory": os.getenv("JACS_KEY_DIRECTORY"),
            "jacs_default_storage": os.getenv("JACS_DEFAULT_STORAGE", "fs"),
            "jacs_agent_key_algorithm": os.getenv("JACS_AGENT_KEY_ALGORITHM", "Ed25519")
        }
    
    # Fall back to config file
    try:
        with open("jacs.config.json", "r") as f:
            return json.load(f)
    except FileNotFoundError:
        # Default configuration
        return {
            "jacs_data_directory": "./jacs_data",
            "jacs_key_directory": "./jacs_keys",
            "jacs_default_storage": "fs",
            "jacs_agent_key_algorithm": "Ed25519"
        }

# Usage
config = load_config()
agent = jacs.Agent(config)
```

### Configuration Validation

```python
def validate_config(config):
    """Validate JACS configuration"""
    required_fields = [
        "jacs_data_directory",
        "jacs_key_directory", 
        "jacs_default_storage",
        "jacs_agent_key_algorithm"
    ]
    
    for field in required_fields:
        if field not in config:
            raise ValueError(f"Missing required configuration field: {field}")
    
    # Validate algorithm
    valid_algorithms = ["Ed25519", "RSA", "Dilithium"]
    if config["jacs_agent_key_algorithm"] not in valid_algorithms:
        raise ValueError(f"Invalid algorithm: {config['jacs_agent_key_algorithm']}")
    
    # Validate storage
    valid_storage = ["fs", "s3", "azure"]
    if config["jacs_default_storage"] not in valid_storage:
        raise ValueError(f"Invalid storage backend: {config['jacs_default_storage']}")
    
    return True

# Usage
try:
    validate_config(config)
    agent = jacs.Agent(config)
except ValueError as e:
    print(f"Configuration error: {e}")
```

## Performance Tips

### Batch Operations

```python
# Create multiple tasks efficiently
tasks_data = [
    {"title": f"Task {i}", "description": f"Description {i}", "status": "pending"}
    for i in range(10)
]

created_tasks = []
for task_data in tasks_data:
    task = agent.create_task(task_data)
    created_tasks.append(task)

print(f"Created {len(created_tasks)} tasks")
```

### Caching Agent Instance

```python
# Cache agent instance for reuse
class JACSManager:
    def __init__(self, config):
        self.config = config
        self._agent = None
    
    @property
    def agent(self):
        if self._agent is None:
            self._agent = jacs.Agent(self.config)
        return self._agent
    
    def create_task(self, task_data):
        return self.agent.create_task(task_data)
    
    def get_task(self, task_id):
        return self.agent.get_task(task_id)

# Usage
manager = JACSManager(config)
task = manager.create_task({"title": "Cached Task", "status": "pending"})
```

## Next Steps

Now that you understand the basics:

1. **[MCP Integration](mcp.md)** - Add Model Context Protocol support
2. **[FastMCP Integration](fastmcp.md)** - Build advanced MCP servers  
3. **[API Reference](api.md)** - Complete API documentation
4. **[Examples](../examples/python.md)** - More complex examples

## Common Patterns

### Task Pipeline

```python
def process_data_pipeline(agent, data_source):
    """Example data processing pipeline using JACS tasks"""
    
    # Create extraction task
    extract_task = agent.create_task({
        "title": "Extract Data",
        "description": f"Extract data from {data_source}",
        "status": "pending",
        "type": "extraction"
    })
    
    # Simulate extraction
    agent.update_task(extract_task['jacsId'], {
        "status": "completed",
        "results": {"records_extracted": 1000}
    })
    
    # Create transformation task
    transform_task = agent.create_task({
        "title": "Transform Data", 
        "description": "Clean and transform extracted data",
        "status": "pending",
        "type": "transformation",
        "depends_on": [extract_task['jacsId']]
    })
    
    # Continue pipeline...
    return [extract_task, transform_task]

# Usage
pipeline_tasks = process_data_pipeline(agent, "customer_database")
print(f"Created pipeline with {len(pipeline_tasks)} tasks")
``` 