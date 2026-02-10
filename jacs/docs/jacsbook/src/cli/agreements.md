# Agreements

Agreements are one of the basic reasons JACS exists. An agreement is a collection of signatures from required agents.
You may want to use it to ensure that agents agree. You can also create human-in-the-loop scenarios, where automated agents sign, but the human using the cli must sign the document for a process to contineu.

If all the agreements are signed.

To create an agreement you need an existing jacs document and agent ids (no version):

    jacs document verify -f  examples/documents/a3b935f3-57c4-4562-9d1a-2c06a89380e7\:4f041628-5a2d-48d3-aa17-a8bd9b9fc00e.json

Then create add a comma separated list of agents where `-i` are the agent identities.

    jacs document create-agreement -f ./examples/documents/newjsonld.json -i 432e0415-5317-4999-abd4-f2a125dab90a, 5305e3e1-9b14-4cb7-94ff-902f9c101d91

To sign the document, sign the new document that was created by `create-agreement`

    jacs document sign-agreement  -f  examples/documents/a3b935f3-57c4-4562-9d1a-2c06a89380e7\:1c37d69f-243a-45d2-aa99-c298af6b1304.json

Now you can check if the agreement was signed. If all agents have signed (or quorum is met), it will succeed. If not enough agents have signed or the agreement has expired, it will error.

    jacs document check-agreement  -f  examples/documents/a3b935f3-57c4-4562-9d1a-2c06a89380e7\:1c37d69f-243a-45d2-aa99-c298af6b1304.json

## Agreement Options (v0.6.2+)

Agreements now support:

- **Timeout**: ISO 8601 deadline after which the agreement expires
- **Quorum**: M-of-N signing (e.g., 2 of 3 agents is sufficient)
- **Algorithm constraints**: Only allow specific signing algorithms (e.g., post-quantum only)

These options are available through the Python `JacsClient`, Node.js `JacsClient`, and MCP tools. See [Agreements in Rust](../rust/agreements.md) for full documentation and examples.

