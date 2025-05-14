


## Usage 


### With MCP

You can use JACS middleware

```js
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { createJacsMiddleware } from 'jacsnpm/mcp';

const server = new McpServer({ name: "MyServer", version: "1.0.0" });
server.use(createJacsMiddleware({ configPath: './config.json' }));
```

Or you can use JACS warpper for simpler syntax

```js
import { JacsMcpServer } from 'jacsnpm/mcp';

const server = new JacsMcpServer({
    name: "MyServer",
    version: "1.0.0",
    configPath: './config.json'
});
```