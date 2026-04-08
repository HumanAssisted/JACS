# Untitled string in Agent Schema

```txt
https://hai.ai/schemas/agent/v1/agent.schema.json#/allOf/1/properties/jacsKeyRotationProof/properties/timestamp
```

ISO 8601 timestamp of the rotation event

| Abstract            | Extensible | Status         | Identifiable            | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                             |
| :------------------ | :--------- | :------------- | :---------------------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | Unknown identifiability | Forbidden         | Allowed               | none                | [agent.schema.json\*](../../schemas/agent/v1/agent.schema.json "open original schema") |

## timestamp Type

`string`

## timestamp Constraints

**date time**: the string must be a date time string, according to [RFC 3339, section 5.6](https://tools.ietf.org/html/rfc3339 "check the specification")
