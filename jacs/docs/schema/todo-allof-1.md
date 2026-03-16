# Untitled object in Todo List Schema

```txt
https://hai.ai/schemas/todo/v1/todo.schema.json#/allOf/1
```



| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                          |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :---------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [todo.schema.json\*](../../schemas/todo/v1/todo.schema.json "open original schema") |

## 1 Type

`object` ([Details](todo-allof-1.md))

# 1 Properties

| Property                                    | Type     | Required | Nullable       | Defined by                                                                                                                                            |
| :------------------------------------------ | :------- | :------- | :------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------- |
| [jacsTodoName](#jacstodoname)               | `string` | Optional | cannot be null | [Todo List](todo-allof-1-properties-jacstodoname.md "https://hai.ai/schemas/todo/v1/todo.schema.json#/allOf/1/properties/jacsTodoName")               |
| [jacsTodoItems](#jacstodoitems)             | `array`  | Optional | cannot be null | [Todo List](todo-allof-1-properties-jacstodoitems.md "https://hai.ai/schemas/todo/v1/todo.schema.json#/allOf/1/properties/jacsTodoItems")             |
| [jacsTodoArchiveRefs](#jacstodoarchiverefs) | `array`  | Optional | cannot be null | [Todo List](todo-allof-1-properties-jacstodoarchiverefs.md "https://hai.ai/schemas/todo/v1/todo.schema.json#/allOf/1/properties/jacsTodoArchiveRefs") |

## jacsTodoName

Human-readable name for this todo list.

`jacsTodoName`

* is optional

* Type: `string`

* cannot be null

* defined in: [Todo List](todo-allof-1-properties-jacstodoname.md "https://hai.ai/schemas/todo/v1/todo.schema.json#/allOf/1/properties/jacsTodoName")

### jacsTodoName Type

`string`

## jacsTodoItems

Inline items (goals and tasks) in this list.

`jacsTodoItems`

* is optional

* Type: `object[]` ([Todo Item](todo-allof-1-properties-jacstodoitems-todo-item.md))

* cannot be null

* defined in: [Todo List](todo-allof-1-properties-jacstodoitems.md "https://hai.ai/schemas/todo/v1/todo.schema.json#/allOf/1/properties/jacsTodoItems")

### jacsTodoItems Type

`object[]` ([Todo Item](todo-allof-1-properties-jacstodoitems-todo-item.md))

## jacsTodoArchiveRefs

UUIDs of archived todo lists (previous versions or completed lists).

`jacsTodoArchiveRefs`

* is optional

* Type: `string[]`

* cannot be null

* defined in: [Todo List](todo-allof-1-properties-jacstodoarchiverefs.md "https://hai.ai/schemas/todo/v1/todo.schema.json#/allOf/1/properties/jacsTodoArchiveRefs")

### jacsTodoArchiveRefs Type

`string[]`
