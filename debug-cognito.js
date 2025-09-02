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

console.log(`${colors.cyan}${colors.bright}=== Cognito Configuration Debug Tool ===${colors.reset}\n`);

// Function to make an HTTP request with detailed error logging
async function makeRequest(url, method = 'HEAD') {
  console.log(`${colors.blue}Making ${method} request to: ${url}${colors.reset}`);
  
  return new Promise((resolve, reject) => {
    const requestLib = url.startsWith('https') ? https : http;
    const parsedUrl = new URL(url);
    
    const options = {
      hostname: parsedUrl.hostname,
      path: parsedUrl.pathname + parsedUrl.search,
      method: method,
      timeout: 10000, // 10 second timeout
      headers: {
        'User-Agent': 'Vendure-Debug-Tool/1.0'
      }
    };
    
    const req = requestLib.request(options, (res) => {
      let data = '';
      
      res.on('data', (chunk) => {
        data += chunk;
      });
      
      res.on('end', () => {
        console.log(`${colors.blue}Response status: ${res.statusCode}${colors.reset}`);
        console.log(`${colors.blue}Response headers: ${JSON.stringify(res.headers)}${colors.reset}`);
        
        if (data && data.length < 1000) {
          console.log(`${colors.blue}Response data: ${data}${colors.reset}`);
        } else if (data) {
          console.log(`${colors.blue}Response data length: ${data.length} bytes${colors.reset}`);
        }
        
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          data: data
        });
      });
    });
    
    req.on('error', (error) => {
      console.log(`${colors.red}Request error: ${error.message}${colors.reset}`);
      if (error.code === 'ENOTFOUND') {
        console.log(`${colors.yellow}The hostname could not be resolved. Check if the domain name is correct.${colors.reset}`);
      } else if (error.code === 'ECONNREFUSED') {
        console.log(`${colors.yellow}Connection refused. The server might be down or not accepting connections.${colors.reset}`);
      }
      reject(error);
    });
    
    req.on('timeout', () => {
      console.log(`${colors.red}Request timeout${colors.reset}`);
      req.abort();
      reject(new Error('Request timed out'));
    });
    
    req.end();
  });
}

// Function to validate environment variables
function validateEnvironment() {
  console.log(`${colors.magenta}Validating environment variables...${colors.reset}`);
  
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
  for (const varName of requiredVars) {
    if (!process.env[varName]) {
      missing.push(varName);
    } else {
      console.log(`${varName}: ${colors.green}✓${colors.reset}`);
    }
  }
  
  if (missing.length > 0) {
    console.log(`${colors.red}Error: Missing required environment variables: ${missing.join(', ')}${colors.reset}`);
    return false;
  }
  
  // Validate format of Cognito domain
  const cognitoDomain = process.env.COGNITO_DOMAIN;
  if (cognitoDomain) {
    // Check if domain contains region
    if (!cognitoDomain.includes(process.env.AWS_REGION.replace('-', ''))) {
      console.log(`${colors.yellow}Warning: COGNITO_DOMAIN (${cognitoDomain}) doesn't contain the AWS region code. The correct format is usually: your-domain-prefix.auth.region.amazoncognito.com${colors.reset}`);
    }
    
    // Check if domain includes '.auth.'
    if (!cognitoDomain.includes('.auth.')) {
      console.log(`${colors.yellow}Warning: COGNITO_DOMAIN (${cognitoDomain}) doesn't contain '.auth.' which is usually present in Cognito domains${colors.reset}`);
    }
  }
  
  // Validate JWKS URL format
  const jwksUrl = process.env.COGNITO_JWKS_URL;
  if (jwksUrl) {
    // Check if URL contains user pool ID
    if (!jwksUrl.includes(process.env.COGNITO_USER_POOL_ID)) {
      console.log(`${colors.yellow}Warning: COGNITO_JWKS_URL doesn't contain the user pool ID. The correct format is usually: https://cognito-idp.[region].amazonaws.com/[user-pool-id]/.well-known/jwks.json${colors.reset}`);
    }
    
    // Check if URL ends with jwks.json
    if (!jwksUrl.endsWith('.well-known/jwks.json')) {
      console.log(`${colors.yellow}Warning: COGNITO_JWKS_URL doesn't end with '.well-known/jwks.json' which is the standard path for JWKS endpoints${colors.reset}`);
    }
  }
  
  return true;
}

// Function to validate COGNITO_LOGIN_URL
function validateLoginUrl() {
  console.log(`\n${colors.magenta}Validating login URL...${colors.reset}`);
  
  try {
    const loginUrl = process.env.COGNITO_LOGIN_URL;
    const url = new URL(loginUrl);
    const params = new URLSearchParams(url.search);
    
    // Check host format
    const expectedHostPrefix = `${process.env.COGNITO_DOMAIN}`;
    if (!url.host.includes(expectedHostPrefix)) {
      console.log(`${colors.yellow}Warning: Login URL host (${url.host}) doesn't match COGNITO_DOMAIN (${expectedHostPrefix})${colors.reset}`);
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
        console.log(`${colors.red}Missing required parameter in login URL: ${param}${colors.reset}`);
        return false;
      }
      
      if (value !== expectedValue) {
        console.log(`${colors.yellow}Warning: Parameter ${param} has value '${value}', expected '${expectedValue}'${colors.reset}`);
      } else {
        console.log(`${param}: ${colors.green}✓${colors.reset}`);
      }
    }
    
    // Check if scope includes required permissions
    const scope = params.get('scope');
    if (!scope) {
      console.log(`${colors.red}Missing 'scope' parameter in login URL${colors.reset}`);
      return false;
    }
    
    const requiredScopes = ['openid', 'email', 'profile'];
    const scopeList = scope.split(' ');
    const missingScopes = requiredScopes.filter(s => !scopeList.includes(s));
    
    if (missingScopes.length > 0) {
      console.log(`${colors.yellow}Warning: Login URL is missing scopes: ${missingScopes.join(', ')}${colors.reset}`);
    } else {
      console.log(`scope: ${colors.green}✓${colors.reset}`);
    }
    
    return true;
  } catch (error) {
    console.log(`${colors.red}Invalid login URL: ${error.message}${colors.reset}`);
    return false;
  }
}

// Function to test connections to Cognito endpoints
async function testConnections() {
  console.log(`\n${colors.magenta}Testing connections to Cognito endpoints...${colors.reset}`);
  
  const cognitoDomain = process.env.COGNITO_DOMAIN;
  const awsRegion = process.env.AWS_REGION;
  
  // Test URLs
  const urls = [
    {
      name: "JWKS URL",
      url: process.env.COGNITO_JWKS_URL,
      method: 'GET'  // JWKS should be accessed with GET
    },
    {
      name: "Cognito Domain",
      url: `https://${cognitoDomain}/ping`,
      method: 'GET'
    },
    {
      name: "OAuth Token Endpoint",
      url: `https://${cognitoDomain}/oauth2/token`,
      method: 'HEAD'  // HEAD is enough to check if endpoint exists
    },
    {
      name: "Cognito Issuer",
      url: process.env.COGNITO_ISSUER,
      method: 'HEAD'
    }
  ];
  
  // Test each URL
  for (const endpoint of urls) {
    console.log(`\n${colors.blue}Testing ${endpoint.name}: ${endpoint.url}${colors.reset}`);
    
    try {
      const startTime = Date.now();
      const response = await makeRequest(endpoint.url, endpoint.method);
      const duration = Date.now() - startTime;
      
      // Different endpoints have different success status codes
      let isSuccess = false;
      if (endpoint.url.includes('oauth2/token') && response.statusCode === 400) {
        // For token endpoint, 400 is expected for HEAD/GET without proper params
        isSuccess = true;
      } else if (response.statusCode >= 200 && response.statusCode < 300) {
        isSuccess = true;
      }
      
      if (isSuccess) {
        console.log(`${colors.green}✓ Successfully connected to ${endpoint.name} (${duration}ms)${colors.reset}`);
      } else {
        console.log(`${colors.red}✗ Failed to connect to ${endpoint.name}: Status ${response.statusCode} (${duration}ms)${colors.reset}`);
      }
      
      // For JWKS endpoint, validate the response
      if (endpoint.name === "JWKS URL" && endpoint.method === 'GET') {
        try {
          const jwksData = JSON.parse(response.data);
          if (jwksData && jwksData.keys && Array.isArray(jwksData.keys)) {
            console.log(`${colors.green}✓ Valid JWKS response with ${jwksData.keys.length} keys${colors.reset}`);
            
            // Show key IDs
            jwksData.keys.forEach((key, index) => {
              console.log(`${colors.green}  - Key ${index + 1}: kid=${key.kid}, kty=${key.kty}, use=${key.use}${colors.reset}`);
            });
          } else {
            console.log(`${colors.red}✗ Invalid JWKS response format${colors.reset}`);
          }
        } catch (e) {
          console.log(`${colors.red}✗ Failed to parse JWKS response: ${e.message}${colors.reset}`);
        }
      }
      
    } catch (error) {
      console.log(`${colors.red}✗ Error connecting to ${endpoint.name}: ${error.message}${colors.reset}`);
    }
  }
}

// Function to try fixing common Cognito URL issues
function suggestUrlFixes() {
  console.log(`\n${colors.magenta}Checking for common URL format issues...${colors.reset}`);
  
  // Check COGNITO_DOMAIN format
  const cognitoDomain = process.env.COGNITO_DOMAIN;
  const awsRegion = process.env.AWS_REGION;
  const userPoolId = process.env.COGNITO_USER_POOL_ID;
  
  if (cognitoDomain) {
    // Check if domain already contains the full URL
    if (cognitoDomain.startsWith('http')) {
      console.log(`${colors.yellow}Warning: COGNITO_DOMAIN should be just the domain name, not a full URL${colors.reset}`);
      console.log(`${colors.yellow}Current: ${cognitoDomain}${colors.reset}`);
      
      try {
        const url = new URL(cognitoDomain);
        console.log(`${colors.green}Suggestion: Set COGNITO_DOMAIN to ${url.hostname}${colors.reset}`);
      } catch (e) {
        // Invalid URL, can't parse it
      }
    }
    
    // Check if domain includes .auth.[region].amazoncognito.com
    const expectedDomainSuffix = `.auth.${awsRegion}.amazoncognito.com`;
    if (!cognitoDomain.includes(expectedDomainSuffix) && !cognitoDomain.includes('http')) {
      console.log(`${colors.yellow}Warning: COGNITO_DOMAIN might be missing the AWS Cognito domain suffix${colors.reset}`);
      console.log(`${colors.green}Suggestion: Set COGNITO_DOMAIN to ${cognitoDomain}${expectedDomainSuffix}${colors.reset}`);
    }
  }
  
  // Check JWKS URL format
  const jwksUrl = process.env.COGNITO_JWKS_URL;
  if (jwksUrl) {
    const expectedJwksUrl = `https://cognito-idp.${awsRegion}.amazonaws.com/${userPoolId}/.well-known/jwks.json`;
    
    if (jwksUrl !== expectedJwksUrl) {
      console.log(`${colors.yellow}Warning: COGNITO_JWKS_URL might not be in the standard format${colors.reset}`);
      console.log(`${colors.yellow}Current: ${jwksUrl}${colors.reset}`);
      console.log(`${colors.green}Standard format: ${expectedJwksUrl}${colors.reset}`);
    }
  }
  
  // Check login URL format
  const loginUrl = process.env.COGNITO_LOGIN_URL;
  if (loginUrl) {
    try {
      const url = new URL(loginUrl);
      
      // Expected path for login
      if (url.pathname !== '/login' && url.pathname !== '/oauth2/authorize') {
        console.log(`${colors.yellow}Warning: Login URL path (${url.pathname}) should typically be '/login' or '/oauth2/authorize'${colors.reset}`);
      }
      
      // Check for proper domain
      const expectedLoginDomain = `${cognitoDomain}`;
      if (!url.host.includes(expectedLoginDomain.toLowerCase())) {
        console.log(`${colors.yellow}Warning: Login URL host doesn't match COGNITO_DOMAIN${colors.reset}`);
        console.log(`${colors.yellow}Current host: ${url.host}${colors.reset}`);
        console.log(`${colors.yellow}Expected to include: ${expectedLoginDomain}${colors.reset}`);
      }
    } catch (e) {
      // Invalid URL, can't parse it
    }
  }
}

// Function to simulate the token exchange process (for educational purposes only)
function simulateTokenExchange() {
  console.log(`\n${colors.magenta}Simulating token exchange process...${colors.reset}`);
  
  const cognitoDomain = process.env.COGNITO_DOMAIN;
  const awsRegion = process.env.AWS_REGION;
  const tokenURL = `https://${cognitoDomain}/oauth2/token`;
  
  console.log(`1. User is redirected to: ${process.env.COGNITO_LOGIN_URL}`);
  console.log(`2. After authentication, Cognito redirects to: ${process.env.PUBLIC_URL}/cognito/callback with authorization code`);
  console.log(`3. Our server exchanges the code for tokens using: ${tokenURL}`);
  console.log(`4. The exchange request includes:`);
  console.log(`   - client_id: ${process.env.COGNITO_CLIENT_ID}`);
  console.log(`   - client_secret: ${process.env.COGNITO_CLIENT_SECRET.substring(0, 3)}...`);
  console.log(`   - grant_type: authorization_code`);
  console.log(`   - redirect_uri: ${process.env.PUBLIC_URL}/cognito/callback`);
  console.log(`   - code: [the authorization code from step 2]`);
  console.log(`5. Cognito returns access_token, id_token, and refresh_token`);
  console.log(`6. Our server verifies the id_token using JWKS from: ${process.env.COGNITO_JWKS_URL}`);
  console.log(`7. After verification, we create or update the user and establish a session`);
  
  console.log(`\n${colors.cyan}To test the complete flow:${colors.reset}`);
  console.log(`1. Visit: ${process.env.PUBLIC_URL}/cognito/login`);
  console.log(`2. Complete the Cognito login process`);
  console.log(`3. You should be redirected back to the admin UI`);
}

// Execute all checks
async function runChecks() {
  let allGood = validateEnvironment();
  
  if (allGood) {
    validateLoginUrl();
  }
  
  // Test connections to endpoints
  await testConnections();
  
  // Check for common URL format issues
  suggestUrlFixes();
  
  // Always show the token exchange simulation
  simulateTokenExchange();
}

runChecks().catch(err => {
  console.error(`${colors.red}Unexpected error: ${err.message}${colors.reset}`);
});
