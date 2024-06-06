# Service Schema

```txt
https://hai.ai/schemas/service/v1/service-schema.json
```

Services that an Agent claims to provide.

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                            |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :---------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Forbidden             | none                | [service.schema.json](../../schemas/components/service/v1/service.schema.json "open original schema") |

## Service Type

`object` ([Service](service.md))

# Service Properties

| Property                                              | Type      | Required | Nullable       | Defined by                                                                                                                                             |
| :---------------------------------------------------- | :-------- | :------- | :------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------- |
| [name](#name)                                         | `string`  | Optional | cannot be null | [Service](service-properties-name.md "https://hai.ai/schemas/service/v1/service-schema.json#/properties/name")                                         |
| [serviceDescription](#servicedescription)             | `string`  | Required | cannot be null | [Service](service-properties-servicedescription.md "https://hai.ai/schemas/service/v1/service-schema.json#/properties/serviceDescription")             |
| [successDescription](#successdescription)             | `string`  | Required | cannot be null | [Service](service-properties-successdescription.md "https://hai.ai/schemas/service/v1/service-schema.json#/properties/successDescription")             |
| [failureDescription](#failuredescription)             | `string`  | Required | cannot be null | [Service](service-properties-failuredescription.md "https://hai.ai/schemas/service/v1/service-schema.json#/properties/failureDescription")             |
| [costDescription](#costdescription)                   | `string`  | Optional | cannot be null | [Service](service-properties-costdescription.md "https://hai.ai/schemas/service/v1/service-schema.json#/properties/costDescription")                   |
| [idealCustomerDescription](#idealcustomerdescription) | `string`  | Optional | cannot be null | [Service](service-properties-idealcustomerdescription.md "https://hai.ai/schemas/service/v1/service-schema.json#/properties/idealCustomerDescription") |
| [termsOfService](#termsofservice)                     | `string`  | Optional | cannot be null | [Service](service-properties-termsofservice.md "https://hai.ai/schemas/service/v1/service-schema.json#/properties/termsOfService")                     |
| [privacyPolicy](#privacypolicy)                       | `string`  | Optional | cannot be null | [Service](service-properties-privacypolicy.md "https://hai.ai/schemas/service/v1/service-schema.json#/properties/privacyPolicy")                       |
| [copyright](#copyright)                               | `string`  | Optional | cannot be null | [Service](service-properties-copyright.md "https://hai.ai/schemas/service/v1/service-schema.json#/properties/copyright")                               |
| [eula](#eula)                                         | `string`  | Optional | cannot be null | [Service](service-properties-eula.md "https://hai.ai/schemas/service/v1/service-schema.json#/properties/eula")                                         |
| [isDev](#isdev)                                       | `boolean` | Optional | cannot be null | [Service](service-properties-isdev.md "https://hai.ai/schemas/service/v1/service-schema.json#/properties/isDev")                                       |
| [tools](#tools)                                       | `array`   | Optional | cannot be null | [Service](service-properties-tools.md "https://hai.ai/schemas/service/v1/service-schema.json#/properties/tools")                                       |
| [piiDesired](#piidesired)                             | `array`   | Optional | cannot be null | [Service](service-properties-piidesired.md "https://hai.ai/schemas/service/v1/service-schema.json#/properties/piiDesired")                             |

## name

Name of service

`name`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Service](service-properties-name.md "https://hai.ai/schemas/service/v1/service-schema.json#/properties/name")

### name Type

`string`

## serviceDescription

Description of basic service provided.

`serviceDescription`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Service](service-properties-servicedescription.md "https://hai.ai/schemas/service/v1/service-schema.json#/properties/serviceDescription")

### serviceDescription Type

`string`

## successDescription

Description of successful delivery of service.

`successDescription`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Service](service-properties-successdescription.md "https://hai.ai/schemas/service/v1/service-schema.json#/properties/successDescription")

### successDescription Type

`string`

## failureDescription

Description of failure of delivery of service.

`failureDescription`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Service](service-properties-failuredescription.md "https://hai.ai/schemas/service/v1/service-schema.json#/properties/failureDescription")

### failureDescription Type

`string`

## costDescription

types of costs

`costDescription`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Service](service-properties-costdescription.md "https://hai.ai/schemas/service/v1/service-schema.json#/properties/costDescription")

### costDescription Type

`string`

## idealCustomerDescription

Description of ideal customer

`idealCustomerDescription`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Service](service-properties-idealcustomerdescription.md "https://hai.ai/schemas/service/v1/service-schema.json#/properties/idealCustomerDescription")

### idealCustomerDescription Type

`string`

## termsOfService

Legal TOS

`termsOfService`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Service](service-properties-termsofservice.md "https://hai.ai/schemas/service/v1/service-schema.json#/properties/termsOfService")

### termsOfService Type

`string`

## privacyPolicy

How data will be used

`privacyPolicy`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Service](service-properties-privacypolicy.md "https://hai.ai/schemas/service/v1/service-schema.json#/properties/privacyPolicy")

### privacyPolicy Type

`string`

## copyright

How can data provided be used

`copyright`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Service](service-properties-copyright.md "https://hai.ai/schemas/service/v1/service-schema.json#/properties/copyright")

### copyright Type

`string`

## eula

End user license agreement

`eula`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Service](service-properties-eula.md "https://hai.ai/schemas/service/v1/service-schema.json#/properties/eula")

### eula Type

`string`

## isDev

Is the test/development version of the service?

`isDev`

*   is optional

*   Type: `boolean`

*   cannot be null

*   defined in: [Service](service-properties-isdev.md "https://hai.ai/schemas/service/v1/service-schema.json#/properties/isDev")

### isDev Type

`boolean`

## tools

URLs and function definitions of of tools that can be called

`tools`

*   is optional

*   Type: unknown\[]

*   cannot be null

*   defined in: [Service](service-properties-tools.md "https://hai.ai/schemas/service/v1/service-schema.json#/properties/tools")

### tools Type

unknown\[]

## piiDesired

Sensitive data desired.

`piiDesired`

*   is optional

*   Type: `string[]`

*   cannot be null

*   defined in: [Service](service-properties-piidesired.md "https://hai.ai/schemas/service/v1/service-schema.json#/properties/piiDesired")

### piiDesired Type

`string[]`
