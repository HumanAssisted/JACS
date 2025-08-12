# Agents


To use JACS you create an `Agent`  and then use it to create docoments that conform to the JACS `Header` format.

First, create a json document that follows the schema for an agent, and use it in the library to start building other things.



```
{
  "$schema": "https://hai.ai/schemas/agent/v1/agent-schema.json",
  "name": "Agent Smith",
  "agentType": "ai",
  "description": "An agent without keys, id or version",
  "favorite-snack": "mango"
}

```

An id, version etc, will be created  when you load the file from the command line

    jacs agent create ./examples/raw/mysecondagent.new.json --create-keys true

Your agent will look something like this and you will have also created keys. The agent is self-signed and all the fields are hashed.
There is also a public and private key created in the directory set with `jacs_key_directory`. DO NOT use the keys included in the repo.


```
{
  "$schema": "https://hai.ai/schemas/agent/v1/agent-schema.json",
  "agentType": "ai",
  "description": "An agent without keys, id or version",
  "jacsId": "809750ec-215d-440f-9e03-f71114924a1d",
  "jacsOriginalDate": "2024-04-11T05:40:15.934777+00:00",
  "jacsOriginalVersion": "8675c919-cb3a-40c8-a716-7f8e04350651",
  "jacsSha256": "45c7af0a701a97907926910df7005a0a69e769380314b1daf15c7186d3c7263f",
  "jacsSignature": {
    "agentID": "809750ec-215d-440f-9e03-f71114924a1d",
    "agentVersion": "8675c919-cb3a-40c8-a716-7f8e04350651",
    "date": "2024-04-11T05:40:15.949350+00:00",
    "fields": [
      "$schema",
      "agentType",
      "description",
      "jacsId",
      "jacsOriginalDate",
      "jacsOriginalVersion",
      "jacsVersion",
      "jacsVersionDate",
      "name"
    ],
    "publicKeyHash": "8878ef8b8eae9420475f692f75bce9b6a0512c4d91e4674ae21330394539c5e6",
    "signature": "LcsuFUqYIVsLfzaDTcXv+HN/ujd+Zv6A1QEiLTSPPHQVRlktmHIX+igd9wgStMVXB0uXH0yZknjJXv/7hQC0J5o5ZuNVN+ITBqG8fg8CEKPAzkQo3zdKfTWBw/GfjyyvItpZzQMGAPoOChS0tc0po5Z8ftOTmsxbfkM4ULGzLrVrhs21i/HpFa8qBzSVyhznwBT4fqOP6b1NZl7IABJS3pQdKbEZ9+Az+O4/Nl55mpfgAppOEbr5XNFIGRKvQ3K5oJS55l6e3GrbH3+5J3bDC1Gxh4wbqYJXVBVKipdJVCtoftEoi1ipTxVtv6j/86egUG7+N1CA6p33q1TXJqwqh4YNFq+9XAAj4X7oSyChA5j4VGegl6x5g+qGMszLGJC2oK6Xalna4dGETe3bjx9+QBQKrYc9T3K3X7Ros0uahiUyx8ekuX25ERGojtYIOpjcGLiPGtp95lbbnX/0cLcbJC2IZjduBeS76RTHlt3/RG5ygbzwK3Pao41wVNJyjLoy5SCi6pguTDjMBGQWjTOfKmK3vv9E8tI6T2lJJqeLtNLIkBpZ2KodqkcTr+80ySehMKglwHBQkjx646afCb+dOwdqhhHQt1gSasQRTxHUWg9NcmZ2uqJoXgQ/mGhsz3b8lgRcZEdA8jf9bxMal3+vWhrY/c3o7y0wiajx838ijYE=",
    "signing_algorithm": "RSA-PSS"
  },
  "jacsVersion": "8675c919-cb3a-40c8-a716-7f8e04350651",
  "jacsVersionDate": "2024-04-11T05:40:15.934777+00:00",
  "name": "Agent Smith"
}

```

You can verify you are set up with this command:

    jacs agent verify  -a ./examples/agent/fe00bb15-8c7f-43ac-9413-5a7bd5bb039d\:1f639f69-b3a7-45d5-b814-bc7b91fb3b97.json

To make it easier to use, add `jacs_agent_id_and_version` to your config and you can just run

    jacs agent verify


## DNS fingerprinting (TXT)

Publish a TXT binding your agent ID to the SHA-256 fingerprint of its public key.

Record name:

```
_v1.agent.jacs.<domain>.
```

TXT value:

```
"v=hai.ai; jacs_agent_id=<GUID>; alg=SHA-256; enc=base64; jac_public_key_hash=<digest>"
```

Emit commands (strict DNS by default):

```bash
jacs agent dns --agent-file ./jacs/agent/<ID:VERSION>.json --domain <example.com>
```

During DNS propagation (allow embedded fallback):

```bash
jacs agent dns --agent-file ./jacs/agent/<ID:VERSION>.json --domain <example.com> \
  --provider cloudflare --encoding base64 --no-dns

jacs agent verify -a ./jacs/agent/<ID:VERSION>.json --no-dns
```

Troubleshooting (DNSSEC):

```bash
dig +dnssec TXT _v1.agent.jacs.<domain>.
delv TXT _v1.agent.jacs.<domain>.
kdig +dnssec TXT _v1.agent.jacs.<domain>.
drill -DNSSEC TXT _v1.agent.jacs.<domain>.
```


