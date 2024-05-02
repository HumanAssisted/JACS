# Contact Schema

```txt
schemas/contact/v1/contact-schema.json
```

How to contact over human channels.

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                                                     |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :----------------------------------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [contact.schema.json](../../https:/hai.ai/schemas/=./schemas/components/contact/v1/contact.schema.json "open original schema") |

## Contact Type

`object` ([Contact](contact.md))

# Contact Properties

| Property                          | Type      | Required | Nullable       | Defined by                                                                                                          |
| :-------------------------------- | :-------- | :------- | :------------- | :------------------------------------------------------------------------------------------------------------------ |
| [firstName](#firstname)           | `string`  | Optional | cannot be null | [Contact](contact-properties-firstname.md "schemas/contact/v1/contact-schema.json#/properties/firstName")           |
| [lastName](#lastname)             | `string`  | Optional | cannot be null | [Contact](contact-properties-lastname.md "schemas/contact/v1/contact-schema.json#/properties/lastName")             |
| [addressName](#addressname)       | `string`  | Optional | cannot be null | [Contact](contact-properties-addressname.md "schemas/contact/v1/contact-schema.json#/properties/addressName")       |
| [phone](#phone)                   | `string`  | Optional | cannot be null | [Contact](contact-properties-phone.md "schemas/contact/v1/contact-schema.json#/properties/phone")                   |
| [email](#email)                   | `string`  | Optional | cannot be null | [Contact](contact-properties-email.md "schemas/contact/v1/contact-schema.json#/properties/email")                   |
| [mailName](#mailname)             | `string`  | Optional | cannot be null | [Contact](contact-properties-mailname.md "schemas/contact/v1/contact-schema.json#/properties/mailName")             |
| [mailAddress](#mailaddress)       | `string`  | Optional | cannot be null | [Contact](contact-properties-mailaddress.md "schemas/contact/v1/contact-schema.json#/properties/mailAddress")       |
| [mailAddressTwo](#mailaddresstwo) | `string`  | Optional | cannot be null | [Contact](contact-properties-mailaddresstwo.md "schemas/contact/v1/contact-schema.json#/properties/mailAddressTwo") |
| [mailState](#mailstate)           | `string`  | Optional | cannot be null | [Contact](contact-properties-mailstate.md "schemas/contact/v1/contact-schema.json#/properties/mailState")           |
| [mailZip](#mailzip)               | `string`  | Optional | cannot be null | [Contact](contact-properties-mailzip.md "schemas/contact/v1/contact-schema.json#/properties/mailZip")               |
| [mailCountry](#mailcountry)       | `string`  | Optional | cannot be null | [Contact](contact-properties-mailcountry.md "schemas/contact/v1/contact-schema.json#/properties/mailCountry")       |
| [isPrimary](#isprimary)           | `boolean` | Optional | cannot be null | [Contact](contact-properties-isprimary.md "schemas/contact/v1/contact-schema.json#/properties/isPrimary")           |

## firstName

First name of Person

`firstName`

* is optional

* Type: `string`

* cannot be null

* defined in: [Contact](contact-properties-firstname.md "schemas/contact/v1/contact-schema.json#/properties/firstName")

### firstName Type

`string`

## lastName

Last name of person

`lastName`

* is optional

* Type: `string`

* cannot be null

* defined in: [Contact](contact-properties-lastname.md "schemas/contact/v1/contact-schema.json#/properties/lastName")

### lastName Type

`string`

## addressName

Location name of address

`addressName`

* is optional

* Type: `string`

* cannot be null

* defined in: [Contact](contact-properties-addressname.md "schemas/contact/v1/contact-schema.json#/properties/addressName")

### addressName Type

`string`

## phone

Contact phone number.

`phone`

* is optional

* Type: `string`

* cannot be null

* defined in: [Contact](contact-properties-phone.md "schemas/contact/v1/contact-schema.json#/properties/phone")

### phone Type

`string`

## email

Description of successful delivery of service.

`email`

* is optional

* Type: `string`

* cannot be null

* defined in: [Contact](contact-properties-email.md "schemas/contact/v1/contact-schema.json#/properties/email")

### email Type

`string`

### email Constraints

**email**: the string must be an email address, according to [RFC 5322, section 3.4.1](https://tools.ietf.org/html/rfc5322 "check the specification")

## mailName

Name to reach at address

`mailName`

* is optional

* Type: `string`

* cannot be null

* defined in: [Contact](contact-properties-mailname.md "schemas/contact/v1/contact-schema.json#/properties/mailName")

### mailName Type

`string`

## mailAddress

Street and Street Address

`mailAddress`

* is optional

* Type: `string`

* cannot be null

* defined in: [Contact](contact-properties-mailaddress.md "schemas/contact/v1/contact-schema.json#/properties/mailAddress")

### mailAddress Type

`string`

## mailAddressTwo

Part two mailing address

`mailAddressTwo`

* is optional

* Type: `string`

* cannot be null

* defined in: [Contact](contact-properties-mailaddresstwo.md "schemas/contact/v1/contact-schema.json#/properties/mailAddressTwo")

### mailAddressTwo Type

`string`

## mailState

State or province

`mailState`

* is optional

* Type: `string`

* cannot be null

* defined in: [Contact](contact-properties-mailstate.md "schemas/contact/v1/contact-schema.json#/properties/mailState")

### mailState Type

`string`

## mailZip

Zipcode

`mailZip`

* is optional

* Type: `string`

* cannot be null

* defined in: [Contact](contact-properties-mailzip.md "schemas/contact/v1/contact-schema.json#/properties/mailZip")

### mailZip Type

`string`

## mailCountry

Country

`mailCountry`

* is optional

* Type: `string`

* cannot be null

* defined in: [Contact](contact-properties-mailcountry.md "schemas/contact/v1/contact-schema.json#/properties/mailCountry")

### mailCountry Type

`string`

## isPrimary

Is the primary way to contact agent.

`isPrimary`

* is optional

* Type: `boolean`

* cannot be null

* defined in: [Contact](contact-properties-isprimary.md "schemas/contact/v1/contact-schema.json#/properties/isPrimary")

### isPrimary Type

`boolean`
