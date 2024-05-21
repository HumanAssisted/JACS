# Untitled string in Signature Schema

```txt
https://hai.ai/schemas/components/signature/v1/signature.schema.json#/properties/signingAlgorithm
```

What signature algorithm was used

| Abstract            | Extensible | Status         | Identifiable            | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                                    |
| :------------------ | :--------- | :------------- | :---------------------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------------------------------------ |
| Can be instantiated | No         | Unknown status | Unknown identifiability | Forbidden         | Allowed               | none                | [signature.schema.json\*](../../schemas/components/signature/v1/signature.schema.json "open original schema") |

## signingAlgorithm Type

`string`

## signingAlgorithm Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value            | Explanation |
| :--------------- | :---------- |
| `"RSA-PSS"`      |             |
| `"ring-Ed25519"` |             |
| `"pq-dilithium"` |             |
