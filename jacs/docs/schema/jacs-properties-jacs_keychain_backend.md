# Untitled string in Config Schema

```txt
https://hai.ai/schemas/jacs.config.schema.json#/properties/jacs_keychain_backend
```

OS keychain backend for password storage. 'auto' detects the platform default. 'disabled' skips keychain entirely (recommended for CI/headless).

| Abstract            | Extensible | Status         | Identifiable            | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                |
| :------------------ | :--------- | :------------- | :---------------------- | :---------------- | :-------------------- | :------------------ | :---------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | Unknown identifiability | Forbidden         | Allowed               | none                | [jacs.config.schema.json\*](../../schemas/jacs.config.schema.json "open original schema") |

## jacs\_keychain\_backend Type

`string`

## jacs\_keychain\_backend Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value                    | Explanation |
| :----------------------- | :---------- |
| `"auto"`                 |             |
| `"macos-keychain"`       |             |
| `"linux-secret-service"` |             |
| `"disabled"`             |             |
