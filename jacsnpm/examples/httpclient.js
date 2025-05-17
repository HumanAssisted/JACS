import jacs from '../index.js';
import http from 'http';  
import assert from 'assert';


async function makeHttpRequest(jacsRequestString, targetHost, targetPort, targetPath) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: targetHost,
      port: targetPort,
      path: targetPath,
      method: 'POST',
      headers: {
        'Content-Type': 'text/plain',  
        'Content-Length': Buffer.byteLength(jacsRequestString),
      },
    };

    const req = http.request(options, (res) => {
      let responseBody = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => {
        responseBody += chunk;
      });
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          resolve(responseBody);
        } else {
          reject(new Error(`HTTP request failed with status ${res.statusCode}: ${responseBody}`));
        }
      });
    });

    req.on('error', (e) => {
      reject(new Error(`Problem with HTTP request: ${e.message}`));
    });

    req.write(jacsRequestString);
    req.end();
  });
}

async function runHttpClient(serverType) {
  let targetHost, targetPort;
  if (serverType === 'koa') {
    targetHost = 'localhost';
    targetPort = 3001;
    console.log("HTTP Client: Targeting Koa server (http://localhost:3001/jacs-echo)");
  } else if (serverType === 'express') {
    targetHost = 'localhost';
    targetPort = 3002;
    console.log("HTTP Client: Targeting Express server (http://localhost:3002/jacs-echo)");
  } else {
    console.error("Invalid server type. Choose 'koa' or 'express'.");
    return;
  }

  try {
    // 1. Load JACS client agent
    await jacs.load("./jacs.client.config.json");
    console.log("HTTP Client: JACS agent loaded successfully.");

    // 2. Prepare payload
    const clientPayload = {
      message: "Hello, secure server!",
      data: {
        id: 123,
        value: "some client data"
      },
      client_timestamp: new Date().toISOString()
    };
    console.log("HTTP Client: Original payload:", clientPayload);

    // 3. Sign the request
    const jacsRequestString = await jacs.signRequest(clientPayload);
    console.log("HTTP Client: JACS Request String (first 60 chars):", jacsRequestString.substring(0, 60) + "...");

    // 4. Send HTTP request
    console.log(`HTTP Client: Sending JACS request to ${serverType} server...`);
    const jacsResponseString = await makeHttpRequest(jacsRequestString, targetHost, targetPort, '/jacs-echo');
    console.log("HTTP Client: Received JACS Response String (first 60 chars):", jacsResponseString.substring(0, 60) + "...");

    // 5. Verify the response
    const verifiedResponse = await jacs.verifyResponse(jacsResponseString);
    console.log("HTTP Client: Verified server response payload:", verifiedResponse.payload);
    
    // Optional: Add assertions
    assert(verifiedResponse.payload.echo.includes(`${serverType} server says hello!`));
    assert.deepStrictEqual(verifiedResponse.payload.received_payload.message, clientPayload.message);
    console.log(`HTTP Client: Successfully communicated with ${serverType} server and verified response!`);

  } catch (error) {
    console.error(`HTTP Client Error (${serverType}):`, error.message);
    if (error.stack) {
        console.error(error.stack);
    }
  }
}

// Determine which server to target based on command-line argument
const targetServer = process.argv[2] || 'koa'; // Default to 'koa'
runHttpClient(targetServer);