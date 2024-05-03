# Untitled string in Config Schema

```txt
https://hai.ai/schemas/jacs.config.schema.json#/properties/jacs_agent_key_algorithm
```

algorithm to use for creating and using keys

| Abstract            | Extensible | Status         | Identifiable            | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                            |
| :------------------ | :--------- | :------------- | :---------------------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------------ |
| Can be instantiated | No         | Unknown status | Unknown identifiability | Forbidden         | Allowed               | none                | [jacs.config.schema.json\*](../../out/jacs.config.schema.json "open original schema") |

## jacs\_agent\_key\_algorithm Type

`string`

## jacs\_agent\_key\_algorithm Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value            | Explanation |
| :--------------- | :---------- |
| `"RSA-PSS"`      |             |
| `"ring-Ed25519"` |             |
| `"pq-dilithium"` |             |
