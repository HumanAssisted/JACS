# Agreements

Agreements are one of the basic reasons JACS exists. An agreement is a collection of signatures from required agents.
If all the agreements are signed.

To create an agreement you need an existing jacs document and agent ids (no version):

    jacs document verify -f  examples/documents/a3b935f3-57c4-4562-9d1a-2c06a89380e7\:4f041628-5a2d-48d3-aa17-a8bd9b9fc00e.json

Then create add a comma separated list of agents

    jacs document create-agreement -f ./examples/documents/newjsonld.json -i 432e0415-5317-4999-abd4-f2a125dab90a, 5305e3e1-9b14-4cb7-94ff-902f9c101d91




    jacs document sign-agreement  -f  examples/documents/a3b935f3-57c4-4562-9d1a-2c06a89380e7\:4f041628-5a2d-48d3-aa17-a8bd9b9fc00e.json
    jacs document check-agreement  -f  examples/documents/a3b935f3-57c4-4562-9d1a-2c06a89380e7\:1c37d69f-243a-45d2-aa99-c298af6b1304.json
    jacs document check-agreement  -f  examples/documents/a3b935f3-57c4-4562-9d1a-2c06a89380e7\:679006d0-c095-4bbc-b4e6-6bb1c7cb6f2b.json


432e0415-5317-4999-abd4-f2a125dab90a:b3699f46-51dc-46b9-8995-9b1b65fea5a4.json
5305e3e1-9b14-4cb7-94ff-902f9c101d91:a2ecf623-64a1-43c6-a8f2-4a6c95552c25.json
fa50799d-38f9-40cc-bda5-e28fab6e04c8:356d263f-0a89-4665-b4ea-7373be3fc8be.json