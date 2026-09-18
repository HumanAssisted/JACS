# Untitled object in Agent Schema

```txt
https://hai.ai/schemas/agent/v1/agent.schema.json#/allOf/1/properties/jacsKeyRotationProof
```

Cryptographic proof that a key rotation was authorized by the previous key holder. Present only on agent versions created by key rotation.

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                             |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [agent.schema.json\*](../../schemas/agent/v1/agent.schema.json "open original schema") |

## jacsKeyRotationProof Type

`object` ([Details](agent-allof-1-properties-jacskeyrotationproof.md))

# jacsKeyRotationProof Properties

| Property                                | Type     | Required | Nullable       | Defined by                                                                                                                                                                                                       |
| :-------------------------------------- | :------- | :------- | :------------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [transitionMessage](#transitionmessage) | `string` | Required | cannot be null | [Agent](agent-allof-1-properties-jacskeyrotationproof-properties-transitionmessage.md "https://hai.ai/schemas/agent/v1/agent.schema.json#/allOf/1/properties/jacsKeyRotationProof/properties/transitionMessage") |
| [signature](#signature)                 | `string` | Required | cannot be null | [Agent](agent-allof-1-properties-jacskeyrotationproof-properties-signature.md "https://hai.ai/schemas/agent/v1/agent.schema.json#/allOf/1/properties/jacsKeyRotationProof/properties/signature")                 |
| [signingAlgorithm](#signingalgorithm)   | `string` | Required | cannot be null | [Agent](agent-allof-1-properties-jacskeyrotationproof-properties-signingalgorithm.md "https://hai.ai/schemas/agent/v1/agent.schema.json#/allOf/1/properties/jacsKeyRotationProof/properties/signingAlgorithm")   |
| [oldPublicKeyHash](#oldpublickeyhash)   | `string` | Required | cannot be null | [Agent](agent-allof-1-properties-jacskeyrotationproof-properties-oldpublickeyhash.md "https://hai.ai/schemas/agent/v1/agent.schema.json#/allOf/1/properties/jacsKeyRotationProof/properties/oldPublicKeyHash")   |
| [newPublicKeyHash](#newpublickeyhash)   | `string` | Required | cannot be null | [Agent](agent-allof-1-properties-jacskeyrotationproof-properties-newpublickeyhash.md "https://hai.ai/schemas/agent/v1/agent.schema.json#/allOf/1/properties/jacsKeyRotationProof/properties/newPublicKeyHash")   |
| [timestamp](#timestamp)                 | `string` | Required | cannot be null | [Agent](agent-allof-1-properties-jacskeyrotationproof-properties-timestamp.md "https://hai.ai/schemas/agent/v1/agent.schema.json#/allOf/1/properties/jacsKeyRotationProof/properties/timestamp")                 |

## transitionMessage

The transition message string: JACS\_KEY\_ROTATION:{agent\_id}:{old\_key\_hash}:{new\_key\_hash}:{timestamp}

`transitionMessage`

* is required

* Type: `string`

* cannot be null

* defined in: [Agent](agent-allof-1-properties-jacskeyrotationproof-properties-transitionmessage.md "https://hai.ai/schemas/agent/v1/agent.schema.json#/allOf/1/properties/jacsKeyRotationProof/properties/transitionMessage")

### transitionMessage Type

`string`

## signature

Base64-encoded signature of the transition message, created with the OLD private key

`signature`

* is required

* Type: `string`

* cannot be null

* defined in: [Agent](agent-allof-1-properties-jacskeyrotationproof-properties-signature.md "https://hai.ai/schemas/agent/v1/agent.schema.json#/allOf/1/properties/jacsKeyRotationProof/properties/signature")

### signature Type

`string`

## signingAlgorithm

The cryptographic algorithm used to create the transition signature (the OLD key's algorithm)

`signingAlgorithm`

* is required

* Type: `string`

* cannot be null

* defined in: [Agent](agent-allof-1-properties-jacskeyrotationproof-properties-signingalgorithm.md "https://hai.ai/schemas/agent/v1/agent.schema.json#/allOf/1/properties/jacsKeyRotationProof/properties/signingAlgorithm")

### signingAlgorithm Type

`string`

## oldPublicKeyHash

SHA-256 hash of the old (pre-rotation) public key

`oldPublicKeyHash`

* is required

* Type: `string`

* cannot be null

* defined in: [Agent](agent-allof-1-properties-jacskeyrotationproof-properties-oldpublickeyhash.md "https://hai.ai/schemas/agent/v1/agent.schema.json#/allOf/1/properties/jacsKeyRotationProof/properties/oldPublicKeyHash")

### oldPublicKeyHash Type

`string`

## newPublicKeyHash

SHA-256 hash of the new (post-rotation) public key

`newPublicKeyHash`

* is required

* Type: `string`

* cannot be null

* defined in: [Agent](agent-allof-1-properties-jacskeyrotationproof-properties-newpublickeyhash.md "https://hai.ai/schemas/agent/v1/agent.schema.json#/allOf/1/properties/jacsKeyRotationProof/properties/newPublicKeyHash")

### newPublicKeyHash Type

`string`

## timestamp

ISO 8601 timestamp of the rotation event

`timestamp`

* is required

* Type: `string`

* cannot be null

* defined in: [Agent](agent-allof-1-properties-jacskeyrotationproof-properties-timestamp.md "https://hai.ai/schemas/agent/v1/agent.schema.json#/allOf/1/properties/jacsKeyRotationProof/properties/timestamp")

### timestamp Type

`string`

### timestamp Constraints

**date time**: the string must be a date time string, according to [RFC 3339, section 5.6](https://tools.ietf.org/html/rfc3339 "check the specification")
