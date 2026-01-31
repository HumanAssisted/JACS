# Task Schema

The Task Schema defines the structure for task documents in JACS. Tasks represent work items with defined states, assigned agents, and completion criteria.

## Schema Location

```
https://hai.ai/schemas/task/v1/task.schema.json
```

## Overview

Task documents manage:
- **Workflow States**: From creation through completion
- **Agent Assignment**: Customer and assigned agent tracking
- **Actions**: Desired outcomes and completion criteria
- **Agreements**: Start and end agreements between parties
- **Relationships**: Sub-tasks, copies, and merges

## Schema Structure

The task schema extends the [Header Schema](document.md):

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://hai.ai/schemas/task/v1/task-schema.json",
  "title": "Task",
  "description": "General schema for stateful resources.",
  "allOf": [
    { "$ref": "https://hai.ai/schemas/header/v1/header.schema.json" },
    { "type": "object", "properties": { ... } }
  ]
}
```

## Task States

Tasks progress through defined workflow states:

| State | Description |
|-------|-------------|
| `creating` | Task is being drafted |
| `rfp` | Request for proposal - seeking agents |
| `proposal` | Agent has submitted a proposal |
| `negotiation` | Terms being negotiated |
| `started` | Work has begun |
| `review` | Work submitted for review |
| `completed` | Task is finished |

```json
{
  "jacsTaskState": "started"
}
```

### State Transitions

```
creating → rfp → proposal → negotiation → started → review → completed
                    ↑_______________|
                (may cycle back for renegotiation)
```

## Task Properties

### Core Fields (from Header)

Tasks inherit all [document header fields](document.md) plus task-specific fields.

### Task-Specific Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `jacsTaskName` | string | No | Human-readable task name |
| `jacsTaskSuccess` | string | No | Description of success criteria |
| `jacsTaskState` | string | Yes | Current workflow state |
| `jacsTaskCustomer` | object | Yes | Customer agent signature |
| `jacsTaskAgent` | object | No | Assigned agent signature |
| `jacsTaskStartDate` | string (date-time) | No | When work started |
| `jacsTaskCompleteDate` | string (date-time) | No | When work completed |
| `jacsTaskActionsDesired` | array | Yes | Required actions |
| `jacsStartAgreement` | object | No | Agreement to begin work |
| `jacsEndAgreement` | object | No | Agreement that work is complete |

### Relationship Fields

| Field | Type | Description |
|-------|------|-------------|
| `jacsTaskSubTaskOf` | array | Parent task IDs |
| `jacsTaskCopyOf` | array | Source task IDs (branching) |
| `jacsTaskMergedTasks` | array | Tasks folded into this one |

## Actions

Actions define what needs to be accomplished:

```json
{
  "jacsTaskActionsDesired": [
    {
      "name": "Create API Endpoint",
      "description": "Build REST endpoint for user registration",
      "cost": {
        "value": 500,
        "unit": "USD"
      },
      "duration": {
        "value": 8,
        "unit": "hours"
      },
      "completionAgreementRequired": true,
      "tools": [...]
    }
  ]
}
```

### Action Schema Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Action name |
| `description` | string | Yes | What needs to be done |
| `tools` | array | No | Tools that can be used |
| `cost` | object | No | Cost estimate |
| `duration` | object | No | Time estimate |
| `completionAgreementRequired` | boolean | No | Requires sign-off |

### Unit Schema

Costs and durations use the unit schema:

```json
{
  "cost": {
    "value": 100,
    "unit": "USD"
  },
  "duration": {
    "value": 2,
    "unit": "days"
  }
}
```

## Agreements

Tasks can include start and end agreements:

### Start Agreement

Signed when parties agree to begin work:

```json
{
  "jacsStartAgreement": {
    "agentIDs": ["customer-uuid", "agent-uuid"],
    "question": "Do you agree to begin this work?",
    "context": "Project XYZ - Phase 1",
    "signatures": [...]
  }
}
```

### End Agreement

Signed when parties agree work is complete:

```json
{
  "jacsEndAgreement": {
    "agentIDs": ["customer-uuid", "agent-uuid"],
    "question": "Do you agree this work is complete?",
    "context": "Final deliverables reviewed",
    "signatures": [...]
  }
}
```

## Complete Example

```json
{
  "$schema": "https://hai.ai/schemas/task/v1/task.schema.json",
  "jacsId": "550e8400-e29b-41d4-a716-446655440000",
  "jacsType": "task",
  "jacsVersion": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "jacsVersionDate": "2024-01-15T10:30:00Z",
  "jacsOriginalVersion": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "jacsOriginalDate": "2024-01-15T10:30:00Z",
  "jacsLevel": "artifact",

  "jacsTaskName": "Build Authentication System",
  "jacsTaskSuccess": "Users can register, login, and manage sessions",
  "jacsTaskState": "started",

  "jacsTaskCustomer": {
    "agentID": "customer-agent-uuid",
    "agentVersion": "customer-version-uuid",
    "date": "2024-01-15T10:30:00Z",
    "signature": "customer-signature...",
    "publicKeyHash": "customer-key-hash",
    "signingAlgorithm": "ring-Ed25519",
    "fields": ["jacsTaskName", "jacsTaskActionsDesired"]
  },

  "jacsTaskAgent": {
    "agentID": "assigned-agent-uuid",
    "agentVersion": "agent-version-uuid",
    "date": "2024-01-16T09:00:00Z",
    "signature": "agent-signature...",
    "publicKeyHash": "agent-key-hash",
    "signingAlgorithm": "ring-Ed25519",
    "fields": ["jacsTaskName", "jacsTaskActionsDesired"]
  },

  "jacsTaskStartDate": "2024-01-16T09:00:00Z",

  "jacsStartAgreement": {
    "agentIDs": ["customer-agent-uuid", "assigned-agent-uuid"],
    "question": "Do you agree to begin work on this task?",
    "signatures": [
      {
        "agentID": "customer-agent-uuid",
        "signature": "...",
        "responseType": "agree",
        "date": "2024-01-16T09:00:00Z"
      },
      {
        "agentID": "assigned-agent-uuid",
        "signature": "...",
        "responseType": "agree",
        "date": "2024-01-16T09:05:00Z"
      }
    ]
  },

  "jacsTaskActionsDesired": [
    {
      "name": "User Registration",
      "description": "Implement user registration with email verification",
      "duration": { "value": 4, "unit": "hours" },
      "completionAgreementRequired": true
    },
    {
      "name": "User Login",
      "description": "Implement secure login with password hashing",
      "duration": { "value": 3, "unit": "hours" },
      "completionAgreementRequired": true
    },
    {
      "name": "Session Management",
      "description": "Implement JWT-based session tokens",
      "duration": { "value": 2, "unit": "hours" },
      "completionAgreementRequired": false
    }
  ],

  "jacsSignature": {
    "agentID": "customer-agent-uuid",
    "agentVersion": "customer-version-uuid",
    "date": "2024-01-15T10:30:00Z",
    "signature": "document-signature...",
    "publicKeyHash": "key-hash...",
    "signingAlgorithm": "ring-Ed25519",
    "fields": ["jacsId", "jacsTaskName", "jacsTaskActionsDesired"]
  }
}
```

## Task Relationships

### Sub-Tasks

Break large tasks into smaller units:

```json
{
  "jacsTaskSubTaskOf": ["parent-task-uuid"]
}
```

### Task Copies (Branching)

Create variations or branches:

```json
{
  "jacsTaskCopyOf": ["original-task-uuid"]
}
```

### Merged Tasks

Combine completed tasks:

```json
{
  "jacsTaskMergedTasks": [
    "subtask-1-uuid",
    "subtask-2-uuid"
  ]
}
```

## Task Workflow

### 1. Creating a Task

```python
import jacs
import json

agent = jacs.JacsAgent()
agent.load('./jacs.config.json')

task = agent.create_document(json.dumps({
    'jacsTaskName': 'Build Feature X',
    'jacsTaskSuccess': 'Feature is deployed and tested',
    'jacsTaskState': 'creating',
    'jacsTaskActionsDesired': [
        {
            'name': 'Implementation',
            'description': 'Write the code',
            'completionAgreementRequired': True
        }
    ]
}), custom_schema='https://hai.ai/schemas/task/v1/task.schema.json')
```

### 2. Assigning an Agent

When an agent accepts the task, add their signature to `jacsTaskAgent` and update state to `started`.

### 3. Signing Start Agreement

Both parties sign the start agreement to confirm work begins.

### 4. Completing Work

Update state to `review`, then both parties sign the end agreement.

### 5. Final Completion

After end agreement is signed by all parties, update state to `completed`.

## State Machine Rules

| Current State | Valid Next States |
|---------------|-------------------|
| `creating` | `rfp` |
| `rfp` | `proposal`, `creating` |
| `proposal` | `negotiation`, `rfp` |
| `negotiation` | `started`, `proposal` |
| `started` | `review` |
| `review` | `completed`, `started` |
| `completed` | (terminal) |

## See Also

- [Document Schema](document.md) - Base document fields
- [Agent Schema](agent.md) - Agent structure
- [Agreements](../rust/agreements.md) - Working with agreements
- [JSON Schemas Overview](overview.md) - Schema architecture
