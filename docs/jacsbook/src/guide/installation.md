# Installation

To install the command line tool for creating and verifying agents and documents

    $ cargo install jacs
    $ jacs --help

If you are working in Rust, add the rust lib to your project

    cargo add jacs


## setting up

First, configure your configuration which are loaded as environment variables.
Create a `jacs.config.json` from [the example](./jacs.config.example.json)
For an explanation see [the schema for the config.](./schemas/jacs.config.schema.json)


To create a config file, you can run

    jacs config create

Which will give you this dialog.

You can use `jacs config read` to check the configs.

Note: Do not use `jacs_private_key_password` in production. Use the environment variable `JACS_PRIVATE_KEY_PASSWORD` in a secure manner. This encrypts a private key needed for signing documents. You can create a new version of your agent with a new key, but this is not ideal.

## developing

The pre-commit hook requires some libraries

See pre-commit

 - install `jq` e.g. `brew install jq`
 - for documentation    `npm install -g @adobe/jsonschema2md`
 - cargo install mdbook

Otherwise it's a standard Rust project.

 - install Rust and your favorite editor
 - see tests, examples, and benches







