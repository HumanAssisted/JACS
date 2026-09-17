# Custom Schemas

JACS allows you to define custom document schemas that extend the base header schema, enabling type-safe, validated documents for your specific use cases.

## Overview

Custom schemas:
- Inherit all JACS header fields (jacsId, jacsVersion, jacsSignature, etc.)
- Add domain-specific fields with validation
- Enable IDE autocompletion and type checking
- Ensure document consistency across your application

## Creating a Custom Schema

### Basic Structure

Custom schemas extend the JACS header using `allOf`:

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://example.com/schemas/invoice.schema.json",
  "title": "Invoice",
  "description": "Invoice document with JACS signing",
  "allOf": [
    { "$ref": "https://hai.ai/schemas/header/v1/header.schema.json" },
    {
      "type": "object",
      "properties": {
        "invoiceNumber": {
          "type": "string",
          "description": "Unique invoice identifier"
        },
        "amount": {
          "type": "number",
          "minimum": 0
        },
        "currency": {
          "type": "string",
          "enum": ["USD", "EUR", "GBP"]
        }
      },
      "required": ["invoiceNumber", "amount"]
    }
  ]
}
```

### Step-by-Step Guide

1. **Create the schema file**

```json
// schemas/order.schema.json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://mycompany.com/schemas/order.schema.json",
  "title": "Order",
  "description": "E-commerce order document",
  "allOf": [
    { "$ref": "https://hai.ai/schemas/header/v1/header.schema.json" },
    {
      "type": "object",
      "properties": {
        "orderId": {
          "type": "string",
          "pattern": "^ORD-[0-9]{6}$"
        },
        "customer": {
          "type": "object",
          "properties": {
            "name": { "type": "string" },
            "email": { "type": "string", "format": "email" }
          },
          "required": ["name", "email"]
        },
        "items": {
          "type": "array",
          "minItems": 1,
          "items": {
            "type": "object",
            "properties": {
              "sku": { "type": "string" },
              "quantity": { "type": "integer", "minimum": 1 },
              "price": { "type": "number", "minimum": 0 }
            },
            "required": ["sku", "quantity", "price"]
          }
        },
        "total": {
          "type": "number",
          "minimum": 0
        },
        "status": {
          "type": "string",
          "enum": ["pending", "processing", "shipped", "delivered", "cancelled"]
        }
      },
      "required": ["orderId", "customer", "items", "total", "status"]
    }
  ]
}
```

2. **Use the schema when creating documents**

```python
import jacs
import json

agent = jacs.JacsAgent()
agent.load('./jacs.config.json')

order = agent.create_document(
    json.dumps({
        'orderId': 'ORD-123456',
        'customer': {
            'name': 'Jane Smith',
            'email': 'jane@example.com'
        },
        'items': [
            {'sku': 'WIDGET-001', 'quantity': 2, 'price': 29.99}
        ],
        'total': 59.98,
        'status': 'pending'
    }),
    custom_schema='./schemas/order.schema.json'
)
```

```javascript
import { JacsAgent } from '@hai.ai/jacs';

const agent = new JacsAgent();
agent.load('./jacs.config.json');

const order = agent.createDocument(
  JSON.stringify({
    orderId: 'ORD-123456',
    customer: {
      name: 'Jane Smith',
      email: 'jane@example.com'
    },
    items: [
      { sku: 'WIDGET-001', quantity: 2, price: 29.99 }
    ],
    total: 59.98,
    status: 'pending'
  }),
  './schemas/order.schema.json'
);
```

## Schema Best Practices

### Use Meaningful IDs

```json
{
  "$id": "https://mycompany.com/schemas/v1/order.schema.json"
}
```

Include version in the path for schema evolution.

### Document Everything

```json
{
  "properties": {
    "status": {
      "type": "string",
      "description": "Current order status in the fulfillment workflow",
      "enum": ["pending", "processing", "shipped", "delivered", "cancelled"]
    }
  }
}
```

### Use Appropriate Validation

```json
{
  "properties": {
    "email": {
      "type": "string",
      "format": "email"
    },
    "phone": {
      "type": "string",
      "pattern": "^\\+?[1-9]\\d{1,14}$"
    },
    "quantity": {
      "type": "integer",
      "minimum": 1,
      "maximum": 1000
    }
  }
}
```

### Group Related Fields

```json
{
  "properties": {
    "shipping": {
      "type": "object",
      "properties": {
        "address": { "type": "string" },
        "city": { "type": "string" },
        "country": { "type": "string" },
        "postalCode": { "type": "string" }
      }
    },
    "billing": {
      "type": "object",
      "properties": {
        "address": { "type": "string" },
        "city": { "type": "string" },
        "country": { "type": "string" },
        "postalCode": { "type": "string" }
      }
    }
  }
}
```

## Advanced Schema Features

### Conditional Validation

Different requirements based on field values:

```json
{
  "allOf": [
    { "$ref": "https://hai.ai/schemas/header/v1/header.schema.json" },
    {
      "type": "object",
      "properties": {
        "paymentMethod": {
          "type": "string",
          "enum": ["credit_card", "bank_transfer", "crypto"]
        }
      }
    }
  ],
  "if": {
    "properties": {
      "paymentMethod": { "const": "credit_card" }
    }
  },
  "then": {
    "properties": {
      "cardLastFour": {
        "type": "string",
        "pattern": "^[0-9]{4}$"
      }
    },
    "required": ["cardLastFour"]
  }
}
```

### Reusable Definitions

```json
{
  "$defs": {
    "address": {
      "type": "object",
      "properties": {
        "street": { "type": "string" },
        "city": { "type": "string" },
        "country": { "type": "string" },
        "postalCode": { "type": "string" }
      },
      "required": ["street", "city", "country"]
    }
  },
  "properties": {
    "shippingAddress": { "$ref": "#/$defs/address" },
    "billingAddress": { "$ref": "#/$defs/address" }
  }
}
```

### Array Constraints

```json
{
  "properties": {
    "tags": {
      "type": "array",
      "items": { "type": "string" },
      "minItems": 1,
      "maxItems": 10,
      "uniqueItems": true
    }
  }
}
```

### Pattern Properties

For dynamic field names:

```json
{
  "properties": {
    "metadata": {
      "type": "object",
      "patternProperties": {
        "^x-": { "type": "string" }
      },
      "additionalProperties": false
    }
  }
}
```

## Schema Inheritance

### Extending Custom Schemas

Create schema hierarchies:

```json
// schemas/base-transaction.schema.json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://example.com/schemas/base-transaction.schema.json",
  "allOf": [
    { "$ref": "https://hai.ai/schemas/header/v1/header.schema.json" },
    {
      "type": "object",
      "properties": {
        "transactionId": { "type": "string" },
        "timestamp": { "type": "string", "format": "date-time" },
        "amount": { "type": "number" }
      },
      "required": ["transactionId", "timestamp", "amount"]
    }
  ]
}
```

```json
// schemas/payment.schema.json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://example.com/schemas/payment.schema.json",
  "allOf": [
    { "$ref": "https://example.com/schemas/base-transaction.schema.json" },
    {
      "type": "object",
      "properties": {
        "paymentMethod": { "type": "string" },
        "processorId": { "type": "string" }
      },
      "required": ["paymentMethod"]
    }
  ]
}
```

## Validation

### Python Validation

```python
import jacs
import json

agent = jacs.JacsAgent()
agent.load('./jacs.config.json')

try:
    # This will fail validation - missing required field
    doc = agent.create_document(
        json.dumps({
            'orderId': 'ORD-123456'
            # Missing: customer, items, total, status
        }),
        custom_schema='./schemas/order.schema.json'
    )
except Exception as e:
    print(f"Validation failed: {e}")
```

### Node.js Validation

```javascript
import { JacsAgent } from '@hai.ai/jacs';

const agent = new JacsAgent();
agent.load('./jacs.config.json');

try {
  // This will fail - invalid enum value
  const doc = agent.createDocument(
    JSON.stringify({
      orderId: 'ORD-123456',
      customer: { name: 'Jane', email: 'jane@example.com' },
      items: [{ sku: 'A', quantity: 1, price: 10 }],
      total: 10,
      status: 'invalid_status'  // Not in enum
    }),
    './schemas/order.schema.json'
  );
} catch (error) {
  console.error('Validation failed:', error.message);
}
```

## Example Schemas

### Medical Record

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://healthcare.example.com/schemas/medical-record.schema.json",
  "title": "Medical Record",
  "allOf": [
    { "$ref": "https://hai.ai/schemas/header/v1/header.schema.json" },
    {
      "type": "object",
      "properties": {
        "patientId": { "type": "string" },
        "recordType": {
          "type": "string",
          "enum": ["visit", "lab_result", "prescription", "diagnosis"]
        },
        "provider": {
          "type": "object",
          "properties": {
            "name": { "type": "string" },
            "npi": { "type": "string", "pattern": "^[0-9]{10}$" }
          }
        },
        "date": { "type": "string", "format": "date" },
        "notes": { "type": "string" },
        "confidential": { "type": "boolean", "default": true }
      },
      "required": ["patientId", "recordType", "provider", "date"]
    }
  ]
}
```

### Legal Contract

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://legal.example.com/schemas/contract.schema.json",
  "title": "Legal Contract",
  "allOf": [
    { "$ref": "https://hai.ai/schemas/header/v1/header.schema.json" },
    {
      "type": "object",
      "properties": {
        "contractNumber": { "type": "string" },
        "parties": {
          "type": "array",
          "minItems": 2,
          "items": {
            "type": "object",
            "properties": {
              "name": { "type": "string" },
              "role": { "type": "string" },
              "agentId": { "type": "string", "format": "uuid" }
            }
          }
        },
        "effectiveDate": { "type": "string", "format": "date" },
        "expirationDate": { "type": "string", "format": "date" },
        "terms": { "type": "string" },
        "jurisdiction": { "type": "string" }
      },
      "required": ["contractNumber", "parties", "effectiveDate", "terms"]
    }
  ]
}
```

### IoT Sensor Reading

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://iot.example.com/schemas/sensor-reading.schema.json",
  "title": "Sensor Reading",
  "allOf": [
    { "$ref": "https://hai.ai/schemas/header/v1/header.schema.json" },
    {
      "type": "object",
      "properties": {
        "deviceId": { "type": "string" },
        "sensorType": {
          "type": "string",
          "enum": ["temperature", "humidity", "pressure", "motion"]
        },
        "value": { "type": "number" },
        "unit": { "type": "string" },
        "timestamp": { "type": "string", "format": "date-time" },
        "location": {
          "type": "object",
          "properties": {
            "latitude": { "type": "number" },
            "longitude": { "type": "number" }
          }
        }
      },
      "required": ["deviceId", "sensorType", "value", "timestamp"]
    }
  ]
}
```

## Schema Versioning

### Version in Path

```json
{
  "$id": "https://example.com/schemas/v1/order.schema.json"
}
```

### Version Field

```json
{
  "properties": {
    "schemaVersion": {
      "type": "string",
      "const": "1.0.0"
    }
  }
}
```

### Migration Strategy

1. Create new schema version
2. Update application to support both versions
3. Migrate existing documents
4. Deprecate old version

## See Also

- [JSON Schemas Overview](../schemas/overview.md) - Built-in schemas
- [Document Schema](../schemas/document.md) - Header fields
- [Configuration](../schemas/configuration.md) - Schema configuration
