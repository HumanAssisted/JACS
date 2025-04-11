## setting up

Once you've installed the jacs cli with `cargo install jacs` 

First, create your configuration which can also be loaded loaded as environment variables.

For an explanation see [the schema for the config.](./schemas/jacs.config.schema.json)
Create a `jacs.config.json` from [the example](./jacs.config.example.json) or use `jacs config create` which will give you this dialog:

```
Please enter the data directory path:
Please enter the key directory path:
Please enter the agent private key filename:
Please enter the agent public key filename:
Please enter the agent key algorithm:
Please enter the agent schema version:
Please enter the header schema version:
Please enter the signature schema version:
Please enter the private key password:
Please enter the agent ID and version:
```

You can use `jacs config read` to check the configs. 
You will probably get the error `Warning: Failed to set some environment variables: Environment variable 'JACS_AGENT_ID_AND_VERSION' is empty` at this point. 

You need to create an agent first.  Go to [cli/agent](./cli/agent)

Note: Do not use `jacs_private_key_password` in production. Instead, use the environment variable `JACS_PRIVATE_KEY_PASSWORD` in a secure manner. This encrypts a private key needed for signing documents. You can create a new version of your agent with a new key, but this is not ideal.



## developing

The pre-commit hook requires some libraries

See pre-commit

 - install `jq` e.g. `brew install jq` or use your package manager (e.g., `apt install jq` for Debian/Ubuntu)
 - for documentation    `npm install -g @adobe/jsonschema2md`
 - cargo install mdbook

Otherwise, it's a standard Rust project.

 - install Rust and your favorite editor
 - see tests, examples, and benches

For a complete guide on setting up a Rust development environment, refer to the [official Rust installation guide](https://www.rust-lang.org/tools/install).

After setting up your environment, you can proceed to the next steps in the documentation to begin working with JACS.
