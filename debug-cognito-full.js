/**
 * Comprehensive Cognito Authentication Debug Tool
 * 
 * This script tests all aspects of Cognito authentication:
 * - Environment variable validation
 * - Connection to Cognito endpoints
 * - Token endpoint validation
 * - JWKS validation and key retrieval
 * - OAuth2 flow simulation
 */

const { OAuth2 } = require('oauth');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const http = require('http');
const https = require('https');
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
  white: "\x1b[37m",
  bright: "\x1b[1m"
};

/**
 * Print a section header
 */
function printHeader(text) {
  console.log(`\n${colors.cyan}${colors.bright}=== ${text} ===${colors.reset}\n`);
}

/**
 * Print a subsection header
 */
function printSubHeader(text) {
  console.log(`\n${colors.magenta}${text}${colors.reset}\n`);
}

/**
 * Print a success message
 */
function printSuccess(text) {
  console.log(`${colors.green}✓ ${text}${colors.reset}`);
}

/**
 * Print an error message
 */
function printError(text) {
  console.log(`${colors.red}✗ ${text}${colors.reset}`);
}

/**
 * Print a warning message
 */
function printWarning(text) {
  console.log(`${colors.yellow}⚠ ${text}${colors.reset}`);
}

/**
 * Print an info message
 */
function printInfo(text) {
  console.log(`${colors.blue}ℹ ${text}${colors.reset}`);
}

/**
 * Print a debug message (detailed info)
 */
function printDebug(text) {
  console.log(`  ${colors.white}${text}${colors.reset}`);
}

/**
 * Validate environment variables
 */
function validateEnvironment() {
  printHeader("Environment Variables");
  
  const requiredVars = [
    'AWS_REGION',
    'COGNITO_USER_POOL_ID',
    'COGNITO_CLIENT_ID',
    'COGNITO_CLIENT_SECRET',
    'COGNITO_DOMAIN',
    'COGNITO_ISSUER',
    'COGNITO_AUDIENCE',
    'COGNITO_JWKS_URL',
    'COGNITO_LOGIN_URL',
    'PUBLIC_URL'
  ];
  
  const missing = [];
  const allVars = {};
  
  for (const varName of requiredVars) {
    if (!process.env[varName]) {
      printError(`Missing ${varName}`);
      missing.push(varName);
    } else {
      // Mask secrets when printing
      if (varName.includes('SECRET')) {
        printSuccess(`${varName}: ${process.env[varName].substring(0, 3)}...`);
        allVars[varName] = `${process.env[varName].substring(0, 3)}...`;
      } else {
        printSuccess(`${varName}: ${process.env[varName]}`);
        allVars[varName] = process.env[varName];
      }
    }
  }
  
  // Validate format of certain variables
  if (process.env.COGNITO_USER_POOL_ID && !process.env.COGNITO_USER_POOL_ID.includes('_')) {
    printWarning(`COGNITO_USER_POOL_ID format looks unusual (expected format: 'region_id')`);
  }
  
  if (process.env.COGNITO_JWKS_URL && !process.env.COGNITO_JWKS_URL.includes('.well-known/jwks.json')) {
    printWarning(`COGNITO_JWKS_URL doesn't contain expected path pattern '.well-known/jwks.json'`);
  }
  
  if (process.env.COGNITO_ISSUER && !process.env.COGNITO_ISSUER.includes(process.env.COGNITO_USER_POOL_ID || '')) {
    printWarning(`COGNITO_ISSUER doesn't contain the user pool ID, which is unusual`);
  }
  
  return {
    success: missing.length === 0,
    missing,
    allVars
  };
}

/**
 * Validate the Cognito login URL
 */
function validateLoginUrl() {
  printHeader("Login URL Validation");
  
  try {
    const loginUrl = process.env.COGNITO_LOGIN_URL;
    if (!loginUrl) {
      printError(`COGNITO_LOGIN_URL is not defined`);
      return { success: false };
    }
    
    printInfo(`Login URL: ${loginUrl}`);
    
    const url = new URL(loginUrl);
    const params = new URLSearchParams(url.search);
    
    // Check domain format
    const expectedHostPrefix = `${process.env.COGNITO_DOMAIN}.auth.${process.env.AWS_REGION}.amazoncognito.com`;
    if (!url.host.includes(expectedHostPrefix.toLowerCase())) {
      printWarning(`Login URL host doesn't match expected pattern: ${expectedHostPrefix}`);
    }
    
    // Check path
    if (url.pathname !== '/login') {
      printWarning(`Login URL path is ${url.pathname}, expected '/login'`);
    }
    
    // Check for required parameters
    const checks = {
      'client_id': process.env.COGNITO_CLIENT_ID,
      'response_type': 'code',
      'redirect_uri': `${process.env.PUBLIC_URL}/cognito/callback`
    };
    
    for (const [param, expectedValue] of Object.entries(checks)) {
      const value = params.get(param);
      if (!value) {
        printError(`Missing required parameter in login URL: ${param}`);
      } else if (value !== expectedValue) {
        printWarning(`Parameter ${param} has value '${value}', expected '${expectedValue}'`);
      } else {
        printSuccess(`Parameter ${param} is correct`);
      }
    }
    
    // Check if scope includes required permissions
    const scope = params.get('scope');
    if (!scope) {
      printError(`Missing 'scope' parameter in login URL`);
    } else {
      const requiredScopes = ['openid', 'email', 'profile'];
      const scopeList = scope.split(' ');
      
      printInfo(`Scopes: ${scope}`);
      
      const missingScopes = requiredScopes.filter(s => !scopeList.includes(s));
      if (missingScopes.length > 0) {
        printWarning(`Login URL is missing scopes: ${missingScopes.join(', ')}`);
      } else {
        printSuccess(`All required scopes are present`);
      }
    }
    
    return { success: true };
  } catch (error) {
    printError(`Error validating login URL: ${error.message}`);
    return { success: false, error };
  }
}

/**
 * Test network connectivity to Cognito endpoints
 */
async function testConnectivity() {
  printHeader("Network Connectivity");
  
  const endpoints = [
    {
      name: 'JWKS Endpoint',
      url: process.env.COGNITO_JWKS_URL
    },
    {
      name: 'Cognito Domain',
      url: `https://${process.env.COGNITO_DOMAIN}.auth.${process.env.AWS_REGION}.amazoncognito.com/ping`
    },
    {
      name: 'Token Endpoint',
      url: `https://${process.env.COGNITO_DOMAIN}.auth.${process.env.AWS_REGION}.amazoncognito.com/oauth2/token`
    }
  ];
  
  const results = {};
  
  for (const endpoint of endpoints) {
    if (!endpoint.url) {
      printWarning(`Cannot test ${endpoint.name} - URL is undefined`);
      results[endpoint.name] = { success: false, error: 'URL undefined' };
      continue;
    }
    
    printSubHeader(`Testing ${endpoint.name}: ${endpoint.url}`);
    
    try {
      const startTime = Date.now();
      
      const response = await new Promise((resolve, reject) => {
        const request = (endpoint.url.startsWith('https') ? https : http).request(
          endpoint.url,
          { method: 'HEAD', timeout: 5000 },
          (res) => {
            resolve({
              statusCode: res.statusCode,
              headers: res.headers
            });
          }
        );
        
        request.on('error', (error) => {
          reject(error);
        });
        
        request.on('timeout', () => {
          request.abort();
          reject(new Error('Request timeout'));
        });
        
        request.end();
      });
      
      const duration = Date.now() - startTime;
      
      // For token endpoint, 400 or 405 is expected for HEAD request
      const isSuccessful = endpoint.url.includes('token') 
        ? (response.statusCode === 400 || response.statusCode === 405) 
        : (response.statusCode >= 200 && response.statusCode < 400);
        
      if (isSuccessful) {
        printSuccess(`Connected to ${endpoint.name} in ${duration}ms (Status: ${response.statusCode})`);
      } else {
        printError(`Failed to connect to ${endpoint.name} - Status code: ${response.statusCode}`);
      }
      
      results[endpoint.name] = {
        success: isSuccessful,
        statusCode: response.statusCode,
        duration,
        headers: response.headers
      };
      
    } catch (error) {
      printError(`Failed to connect to ${endpoint.name}: ${error.message}`);
      results[endpoint.name] = { success: false, error: error.message };
    }
  }
  
  return results;
}

/**
 * Validate and retrieve JWKS keys
 */
async function validateJwks() {
  printHeader("JWKS Validation");
  
  try {
    const jwksUri = process.env.COGNITO_JWKS_URL;
    if (!jwksUri) {
      printError(`COGNITO_JWKS_URL is not defined`);
      return { success: false };
    }
    
    printInfo(`Testing connection to: ${jwksUri}`);
    
    const client = jwksClient({
      jwksUri,
      timeout: 10000,
      requestHeaders: {}, // Add custom headers if needed
    });
    
    const keys = await new Promise((resolve, reject) => {
      client.getKeys((err, keys) => {
        if (err) {
          reject(err);
          return;
        }
        resolve(keys);
      });
    });
    
    if (!keys || keys.length === 0) {
      printWarning(`No keys returned from JWKS endpoint`);
      return { success: false, keys: [] };
    }
    
    printSuccess(`Retrieved ${keys.length} keys from JWKS endpoint`);
    
    // Print key details
    keys.forEach((key, index) => {
      printInfo(`Key ${index + 1}:`);
      printDebug(`Kid: ${key.kid}`);
      printDebug(`Kty: ${key.kty}`);
      printDebug(`Use: ${key.use}`);
      printDebug(`Alg: ${key.alg}`);
    });
    
    return { success: true, keys };
  } catch (error) {
    printError(`Error validating JWKS: ${error.message}`);
    if (error.stack) {
      printDebug(`Stack trace: ${error.stack}`);
    }
    return { success: false, error };
  }
}

/**
 * Simulate the OAuth2 token exchange process
 */
function simulateOauth2Exchange() {
  printHeader("OAuth2 Token Exchange Simulation");
  
  const cognitoDomain = process.env.COGNITO_DOMAIN;
  const awsRegion = process.env.AWS_REGION;
  const clientId = process.env.COGNITO_CLIENT_ID;
  const clientSecret = process.env.COGNITO_CLIENT_SECRET;
  const redirectUri = `${process.env.PUBLIC_URL}/cognito/callback`;
  
  if (!cognitoDomain || !awsRegion || !clientId || !clientSecret) {
    printError(`Missing required OAuth2 configuration values`);
    return { success: false };
  }
  
  const tokenURL = `https://${cognitoDomain}.auth.${awsRegion}.amazoncognito.com/oauth2/token`;
  
  printInfo(`Token URL: ${tokenURL}`);
  printInfo(`Client ID: ${clientId}`);
  printInfo(`Redirect URI: ${redirectUri}`);
  
  // Create OAuth2 client
  const oauth2 = new OAuth2(
    clientId,
    clientSecret,
    '',
    '',
    tokenURL
  );
  
  // Simulate what would be sent in the token exchange
  const params = {
    grant_type: 'authorization_code',
    code: 'SIMULATED_CODE',
    redirect_uri: redirectUri
  };
  
  // Show what headers would be sent
  const auth = `${clientId}:${clientSecret}`;
  const encodedAuth = Buffer.from(auth).toString('base64');
  
  printSubHeader("Request Details");
  printDebug(`Method: POST`);
  printDebug(`URL: ${tokenURL}`);
  printDebug(`Headers:`);
  printDebug(`  Authorization: Basic ${encodedAuth.substring(0, 10)}...`);
  printDebug(`  Content-Type: application/x-www-form-urlencoded`);
  printDebug(`Body: ${new URLSearchParams(params).toString()}`);
  
  printSubHeader("Expected Response Structure");
  printDebug(`{`);
  printDebug(`  "access_token": "eyJraWQ...",`);
  printDebug(`  "id_token": "eyJraWQ...",`);
  printDebug(`  "refresh_token": "eyJjdHk...",`);
  printDebug(`  "expires_in": 3600,`);
  printDebug(`  "token_type": "Bearer"`);
  printDebug(`}`);
  
  return { success: true };
}

/**
 * Explain the authentication flow
 */
function explainAuthFlow() {
  printHeader("Authentication Flow");
  
  printInfo(`1. User visits ${process.env.PUBLIC_URL}/cognito/login`);
  printInfo(`2. Server redirects to: ${process.env.COGNITO_LOGIN_URL}`);
  printInfo(`3. User authenticates with Cognito`);
  printInfo(`4. Cognito redirects to: ${process.env.PUBLIC_URL}/cognito/callback?code=xxxx`);
  printInfo(`5. Server exchanges code for tokens with Cognito`);
  printInfo(`6. Server verifies tokens using JWKS`);
  printInfo(`7. Server creates/updates user record and establishes session`);
  printInfo(`8. User is redirected to the admin UI`);
}

/**
 * Check for common issues and provide troubleshooting steps
 */
function troubleshootingGuide(results) {
  printHeader("Troubleshooting Guide");
  
  const issues = [];
  
  // Check for common issues based on results
  if (results.environment && !results.environment.success) {
    issues.push({
      problem: "Missing environment variables",
      solution: `Add the following to your .env file: ${results.environment.missing.join(', ')}`
    });
  }
  
  if (results.connectivity) {
    for (const [name, result] of Object.entries(results.connectivity)) {
      if (!result.success) {
        issues.push({
          problem: `Cannot connect to ${name}`,
          solution: `Check network connectivity, firewall settings, and verify the URL is correct.`
        });
      }
    }
  }
  
  if (results.jwks && !results.jwks.success) {
    issues.push({
      problem: "JWKS endpoint issues",
      solution: "Verify the COGNITO_JWKS_URL is correctly formatted as https://cognito-idp.[region].amazonaws.com/[user-pool-id]/.well-known/jwks.json"
    });
  }
  
  // Check for other common issues
  const redirectUri = `${process.env.PUBLIC_URL}/cognito/callback`;
  issues.push({
    problem: "Potential callback URL mismatch",
    solution: `Ensure the redirect URI "${redirectUri}" is registered in your Cognito app client settings.`
  });
  
  if (process.env.COGNITO_LOGIN_URL && !process.env.COGNITO_LOGIN_URL.includes(encodeURIComponent(redirectUri))) {
    issues.push({
      problem: "Login URL redirect_uri parameter may be incorrect",
      solution: `Check that the redirect_uri in COGNITO_LOGIN_URL matches the application's callback endpoint: ${redirectUri}`
    });
  }
  
  // Display the issues
  if (issues.length === 0) {
    printSuccess("No common issues detected. If you're still having problems, check the logs for detailed error messages.");
  } else {
    for (let i = 0; i < issues.length; i++) {
      const issue = issues[i];
      printSubHeader(`Issue ${i+1}: ${issue.problem}`);
      printInfo(`Solution: ${issue.solution}`);
    }
  }
  
  printSubHeader("Common Error Codes");
  printDebug("invalid_grant: Usually means the authorization code has expired or was already used");
  printDebug("invalid_client: Client authentication failed (wrong client ID or secret)");
  printDebug("invalid_request: Missing required parameter or parameter is malformed");
  printDebug("unauthorized_client: The client is not authorized to use the requested grant type");
  
  printSubHeader("Debug Command");
  printDebug(`Visit ${process.env.PUBLIC_URL}/cognito/test-connection to test connections directly from the server`);
  printDebug(`Visit ${process.env.PUBLIC_URL}/cognito/login?debug=true to enable debug mode during login`);
}

/**
 * Print a summary of all tests
 */
function printSummary(results) {
  printHeader("Summary");
  
  let allSuccess = true;
  
  if (results.environment) {
    const status = results.environment.success ? `${colors.green}PASS` : `${colors.red}FAIL`;
    console.log(`Environment Variables: ${status}${colors.reset}`);
    allSuccess = allSuccess && results.environment.success;
  }
  
  if (results.loginUrl) {
    const status = results.loginUrl.success ? `${colors.green}PASS` : `${colors.red}FAIL`;
    console.log(`Login URL: ${status}${colors.reset}`);
    allSuccess = allSuccess && results.loginUrl.success;
  }
  
  if (results.connectivity) {
    for (const [name, result] of Object.entries(results.connectivity)) {
      const status = result.success ? `${colors.green}PASS` : `${colors.red}FAIL`;
      console.log(`${name}: ${status}${colors.reset}`);
      allSuccess = allSuccess && result.success;
    }
  }
  
  if (results.jwks) {
    const status = results.jwks.success ? `${colors.green}PASS` : `${colors.red}FAIL`;
    console.log(`JWKS: ${status}${colors.reset}`);
    allSuccess = allSuccess && results.jwks.success;
  }
  
  if (results.oauth2) {
    const status = results.oauth2.success ? `${colors.green}PASS` : `${colors.red}FAIL`;
    console.log(`OAuth2 Simulation: ${status}${colors.reset}`);
    allSuccess = allSuccess && results.oauth2.success;
  }
  
  if (allSuccess) {
    console.log(`\n${colors.green}${colors.bright}All tests passed! Your configuration looks good.${colors.reset}`);
    console.log(`\nTry the authentication flow by visiting: ${process.env.PUBLIC_URL}/cognito/login`);
  } else {
    console.log(`\n${colors.yellow}${colors.bright}Some tests failed. Review the issues above and fix them.${colors.reset}`);
    console.log(`\nSee the troubleshooting section for guidance.`);
  }
}

/**
 * Run all tests
 */
async function runTests() {
  console.log(`${colors.cyan}${colors.bright}=== Cognito Authentication Debug Tool ===${colors.reset}\n`);
  
  const results = {
    environment: validateEnvironment(),
    loginUrl: validateLoginUrl()
  };
  
  // Only continue if basic configuration is available
  if (results.environment.success) {
    results.connectivity = await testConnectivity();
    results.jwks = await validateJwks();
    results.oauth2 = simulateOauth2Exchange();
    explainAuthFlow();
  } else {
    printWarning("Skipping connectivity tests due to missing environment variables");
  }
  
  troubleshootingGuide(results);
  printSummary(results);
}

// Run all tests and handle any unexpected errors
runTests().catch(err => {
  console.error(`${colors.red}Unexpected error: ${err.message}${colors.reset}`);
  if (err.stack) {
    console.error(`${colors.red}${err.stack}${colors.reset}`);
  }
});
