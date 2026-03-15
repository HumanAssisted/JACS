# Todo List Schema

```txt
https://hai.ai/schemas/todo/v1/todo.schema.json
```

A private, signed todo list belonging to a single agent. Contains inline items (goals and tasks). The entire list is one signed document. When anything changes, the list is re-signed with a new jacsVersion.

| Abstract            | Extensible | Status         | Identifiable            | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                        |
| :------------------ | :--------- | :------------- | :---------------------- | :---------------- | :-------------------- | :------------------ | :-------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | Unknown identifiability | Forbidden         | Allowed               | none                | [todo.schema.json](../../schemas/todo/v1/todo.schema.json "open original schema") |

## Todo List Type

merged type ([Todo List](todo.md))

all of

* [Header](todo-allof-header.md "check type definition")

* [Untitled object in Todo List](todo-allof-1.md "check type definition")
