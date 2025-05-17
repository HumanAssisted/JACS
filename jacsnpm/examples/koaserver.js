import Koa from 'koa';
import { createJacsMiddleware } from './http.js';  

const app = new Koa();
const jacsMiddleware = createJacsMiddleware({ configPath: './jacs.server.config.json' });

// Raw body capture middleware (might be needed before JACS middleware)
// app.use(async (ctx, next) => {
//   // Logic to capture raw body and put it on ctx.request if not already there
//   await next();
// });

app.use(jacsMiddleware);

app.use(async ctx => {
  // ctx.request now contains the verified JACS payload
  console.log("Verified request payload:", ctx.request);

  // Your business logic
  ctx.response = { message: "Hello from the JACS-protected server!", data: ctx.request };
  // jacsMiddleware will sign ctx.response before sending
});

app.listen(3000);
