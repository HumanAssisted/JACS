# Untitled string in Signature Schema

```txt
https://hai.ai/schemas/components/signature/v1/signature.schema.json#/properties/signatureContentVersion
```

Canonical signature preimage version. New signatures use jacs-signature-v2, which binds signed field names and signature metadata.

| Abstract            | Extensible | Status         | Identifiable            | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                                    |
| :------------------ | :--------- | :------------- | :---------------------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------------------------------------ |
| Can be instantiated | No         | Unknown status | Unknown identifiability | Forbidden         | Allowed               | none                | [signature.schema.json\*](../../schemas/components/signature/v1/signature.schema.json "open original schema") |

## signatureContentVersion Type

`string`

## signatureContentVersion Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value                 | Explanation |
| :-------------------- | :---------- |
| `"jacs-signature-v2"` |             |
