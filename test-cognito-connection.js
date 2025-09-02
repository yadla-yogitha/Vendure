const https = require('https');
const http = require('http');
require('dotenv').config();

// ANSI color codes for better console output
const colors = {
  reset: "\x1b[0m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  magenta: "\x1b[35m",
  cyan: "\x1b[36m",
  white: "\x1b[37m"
};

console.log(`${colors.cyan}=== Cognito Connection Test ===${colors.reset}`);

// Function to make an HTTP request with detailed error handling
function makeRequest(url, method = 'GET', headers = {}) {
  return new Promise((resolve, reject) => {
    console.log(`\n${colors.blue}Making ${method} request to: ${url}${colors.reset}`);
    
    try {
      const parsedUrl = new URL(url);
      const options = {
        hostname: parsedUrl.hostname,
        port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
        path: parsedUrl.pathname + parsedUrl.search,
        method: method,
        headers: {
          'User-Agent': 'Vendure-Cognito-Tester/1.0',
          ...headers
        },
        timeout: 10000 // 10 second timeout
      };
      
      console.log(`${colors.white}Request details:${colors.reset}`);
      console.log(`${colors.white}- Protocol: ${parsedUrl.protocol}${colors.reset}`);
      console.log(`${colors.white}- Hostname: ${options.hostname}${colors.reset}`);
      console.log(`${colors.white}- Port: ${options.port}${colors.reset}`);
      console.log(`${colors.white}- Path: ${options.path}${colors.reset}`);
      console.log(`${colors.white}- Headers: ${JSON.stringify(options.headers)}${colors.reset}`);
      
      const requestLib = parsedUrl.protocol === 'https:' ? https : http;
      const req = requestLib.request(options, (res) => {
        let data = '';
        
        res.on('data', (chunk) => {
          data += chunk;
        });
        
        res.on('end', () => {
          console.log(`${colors.green}Response received:${colors.reset}`);
          console.log(`${colors.green}- Status: ${res.statusCode}${colors.reset}`);
          console.log(`${colors.green}- Headers: ${JSON.stringify(res.headers)}${colors.reset}`);
          
          if (data) {
            // Attempt to parse JSON response
            try {
              const jsonData = JSON.parse(data);
              console.log(`${colors.green}- Body (JSON): ${JSON.stringify(jsonData, null, 2).substring(0, 500)}${colors.reset}`);
              if (jsonData.error) {
                console.log(`${colors.yellow}- Error: ${jsonData.error}${colors.reset}`);
                if (jsonData.error_description) {
                  console.log(`${colors.yellow}- Error Description: ${jsonData.error_description}${colors.reset}`);
                }
              }
            } catch (e) {
              // Not JSON, show as text
              console.log(`${colors.green}- Body (text): ${data.substring(0, 500)}${colors.reset}`);
              if (data.length > 500) console.log(`${colors.green}... (truncated)${colors.reset}`);
            }
          }
          
          resolve({ statusCode: res.statusCode, headers: res.headers, body: data });
        });
      });
      
      req.on('error', (error) => {
        console.log(`${colors.red}Request error: ${error.message}${colors.reset}`);
        
        // Provide more context for common errors
        if (error.code === 'ENOTFOUND') {
          console.log(`${colors.red}DNS resolution failed. Check if the hostname "${options.hostname}" is correct.${colors.reset}`);
          console.log(`${colors.yellow}Suggestion: Verify COGNITO_DOMAIN in .env is correct${colors.reset}`);
        } else if (error.code === 'ECONNREFUSED') {
          console.log(`${colors.red}Connection refused. The server at ${options.hostname}:${options.port} refused the connection.${colors.reset}`);
        } else if (error.code === 'ETIMEDOUT') {
          console.log(`${colors.red}Connection timed out. The server at ${options.hostname}:${options.port} didn't respond in time.${colors.reset}`);
        } else if (error.code === 'ECONNRESET') {
          console.log(`${colors.red}Connection reset by peer. The server at ${options.hostname}:${options.port} abruptly closed the connection.${colors.reset}`);
        }
        
        reject(error);
      });
      
      req.on('timeout', () => {
        console.log(`${colors.red}Request timed out after 10 seconds${colors.reset}`);
        req.abort();
        reject(new Error('Request timed out'));
      });
      
      req.end();
    } catch (error) {
      console.log(`${colors.red}Error creating request: ${error.message}${colors.reset}`);
      reject(error);
    }
  });
}

// Test JWKS URL
async function testJwksUrl() {
  const jwksUrl = process.env.COGNITO_JWKS_URL;
  if (!jwksUrl) {
    console.log(`${colors.red}COGNITO_JWKS_URL is not defined in .env file${colors.reset}`);
    return;
  }
  
  console.log(`${colors.magenta}Testing JWKS endpoint...${colors.reset}`);
  try {
    const response = await makeRequest(jwksUrl);
    
    if (response.statusCode >= 200 && response.statusCode < 300) {
      console.log(`${colors.green}JWKS endpoint is accessible!${colors.reset}`);
      
      // Try to parse JWKS response
      try {
        const jwks = JSON.parse(response.body);
        if (jwks && jwks.keys && Array.isArray(jwks.keys)) {
          console.log(`${colors.green}Valid JWKS response with ${jwks.keys.length} keys${colors.reset}`);
        } else {
          console.log(`${colors.yellow}JWKS response doesn't contain a 'keys' array${colors.reset}`);
        }
      } catch (e) {
        console.log(`${colors.yellow}Could not parse JWKS response as JSON: ${e.message}${colors.reset}`);
      }
    } else {
      console.log(`${colors.red}JWKS endpoint returned status code ${response.statusCode}${colors.reset}`);
    }
  } catch (error) {
    console.log(`${colors.red}Failed to access JWKS endpoint: ${error.message}${colors.reset}`);
  }
}

// Test Cognito domain
async function testCognitoDomain() {
  const cognitoDomain = process.env.COGNITO_DOMAIN;
  if (!cognitoDomain) {
    console.log(`${colors.red}COGNITO_DOMAIN is not defined in .env file${colors.reset}`);
    return;
  }
  
  console.log(`${colors.magenta}Testing Cognito domain...${colors.reset}`);
  
  // Full URL with https://
  const domainUrl = cognitoDomain.startsWith('http') ? 
    cognitoDomain : 
    `https://${cognitoDomain}`;
  
  try {
    // Try root path first
    console.log(`${colors.blue}Testing domain root...${colors.reset}`);
    await makeRequest(`${domainUrl}/`);
  } catch (error) {
    console.log(`${colors.red}Failed to access domain root: ${error.message}${colors.reset}`);
  }
  
  try {
    // Then try login path
    console.log(`${colors.blue}Testing login path...${colors.reset}`);
    await makeRequest(`${domainUrl}/login`);
  } catch (error) {
    console.log(`${colors.red}Failed to access login path: ${error.message}${colors.reset}`);
  }
  
  try {
    // Then try oauth2 path
    console.log(`${colors.blue}Testing OAuth2 path...${colors.reset}`);
    await makeRequest(`${domainUrl}/oauth2/authorize`);
  } catch (error) {
    console.log(`${colors.red}Failed to access OAuth2 path: ${error.message}${colors.reset}`);
  }
}

// Test token endpoint
async function testTokenEndpoint() {
  const cognitoDomain = process.env.COGNITO_DOMAIN;
  if (!cognitoDomain) {
    console.log(`${colors.red}COGNITO_DOMAIN is not defined in .env file${colors.reset}`);
    return;
  }
  
  console.log(`${colors.magenta}Testing token endpoint...${colors.reset}`);
  
  const domainUrl = cognitoDomain.startsWith('http') ?
    cognitoDomain :
    `https://${cognitoDomain}`;
  
  const tokenUrl = `${domainUrl}/oauth2/token`;
  
  try {
    // First just check if endpoint exists
    const response = await makeRequest(tokenUrl, 'POST', {
      'Content-Type': 'application/x-www-form-urlencoded'
    });
    
    // Token endpoint should return 400 if no params or 401 if unauthorized
    if (response.statusCode === 400 || response.statusCode === 401) {
      console.log(`${colors.green}Token endpoint is accessible and responding correctly!${colors.reset}`);
    } else {
      console.log(`${colors.yellow}Token endpoint returned unexpected status code ${response.statusCode}${colors.reset}`);
    }
  } catch (error) {
    console.log(`${colors.red}Failed to access token endpoint: ${error.message}${colors.reset}`);
  }
}

// Run all tests
async function runAllTests() {
  console.log(`${colors.blue}Environment variables:${colors.reset}`);
  console.log(`AWS_REGION: ${process.env.AWS_REGION}`);
  console.log(`COGNITO_USER_POOL_ID: ${process.env.COGNITO_USER_POOL_ID}`);
  console.log(`COGNITO_CLIENT_ID: ${process.env.COGNITO_CLIENT_ID}`);
  console.log(`COGNITO_DOMAIN: ${process.env.COGNITO_DOMAIN}`);
  console.log(`COGNITO_JWKS_URL: ${process.env.COGNITO_JWKS_URL}`);
  console.log(`COGNITO_ISSUER: ${process.env.COGNITO_ISSUER}`);
  
  await testJwksUrl();
  await testCognitoDomain();
  await testTokenEndpoint();
  
  console.log(`\n${colors.cyan}=== Testing complete ===${colors.reset}`);
}

// Run the tests
runAllTests().catch(err => {
  console.error(`${colors.red}Unexpected error: ${err.message}${colors.reset}`);
  if (err.stack) {
    console.error(`${colors.red}Stack trace: ${err.stack}${colors.reset}`);
  }
});
