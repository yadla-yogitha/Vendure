import { Controller, Get, Req, Res, Query } from '@nestjs/common';
import { Request, Response } from 'express';
import { CognitoAuthStrategy } from './cognito-auth-strategy';
import { Logger } from '@vendure/core';
import jwksRsa from 'jwks-rsa';

@Controller('cognito')
export class CognitoAuthController {
    constructor(
        private cognitoAuthStrategy: CognitoAuthStrategy
    ) {
        Logger.info('CognitoAuthController initialized', 'CognitoAuthController');
        
        // Check if the strategy is properly initialized
        try {
            Logger.info('Checking if CognitoAuthStrategy is initialized', 'CognitoAuthController');
            // Check if the strategy has the initialized property and log its value
            if ('initialized' in this.cognitoAuthStrategy) {
                Logger.info(`Strategy initialization status: ${this.cognitoAuthStrategy['initialized'] ? 'initialized' : 'not initialized'}`, 'CognitoAuthController');
            } else {
                Logger.warn('Could not determine if strategy is initialized', 'CognitoAuthController');
            }
        } catch (e) {
            Logger.error(`Error checking strategy initialization: ${e instanceof Error ? e.message : String(e)}`, 'CognitoAuthController');
        }
    }

    @Get('login')
    login(@Res() res: Response, @Query('debug') debug?: string) {
        const loginUrl = process.env.COGNITO_LOGIN_URL;
        if (!loginUrl) {
            const error = 'COGNITO_LOGIN_URL environment variable is not set';
            Logger.error(error, 'CognitoAuthController');
            return res.status(500).send('Authentication configuration error: Missing login URL');
        }
        
        // Add debug parameter if requested
        const finalUrl = debug === 'true' 
            ? `${loginUrl}&state=debug`
            : loginUrl;
            
        Logger.info(`Redirecting to Cognito login: ${finalUrl}`, 'CognitoAuthController');
        
        // Log all env variables related to Cognito (safely)
        const envVars = {
            AWS_REGION: process.env.AWS_REGION,
            COGNITO_USER_POOL_ID: process.env.COGNITO_USER_POOL_ID,
            COGNITO_CLIENT_ID: process.env.COGNITO_CLIENT_ID,
            COGNITO_DOMAIN: process.env.COGNITO_DOMAIN,
            COGNITO_JWKS_URL: process.env.COGNITO_JWKS_URL,
            COGNITO_ISSUER: process.env.COGNITO_ISSUER,
            COGNITO_AUDIENCE: process.env.COGNITO_AUDIENCE,
            PUBLIC_URL: process.env.PUBLIC_URL
        };
        
        Logger.info(`Cognito environment configuration: ${JSON.stringify(envVars)}`, 'CognitoAuthController');
        
        res.redirect(finalUrl);
    }

    @Get()
    index(@Res() res: Response) {
        Logger.info('Cognito index route accessed', 'CognitoAuthController');
        return res.send(`
            <html>
                <head>
                    <title>Cognito Auth</title>
                    <style>
                        body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
                        h1 { color: #333; }
                        .btn { 
                            display: inline-block; 
                            background: #4285F4; 
                            color: white; 
                            padding: 10px 20px; 
                            text-decoration: none; 
                            border-radius: 4px; 
                            margin: 10px 0;
                        }
                    </style>
                </head>
                <body>
                    <h1>Cognito Authentication</h1>
                    <p>Click the button below to authenticate with Cognito:</p>
                    <a href="/cognito/login" class="btn">Login with Cognito</a>
                    
                    <h2>Debug Tools</h2>
                    <p>Use these links for debugging the Cognito integration:</p>
                    <ul>
                        <li><a href="/cognito/debug">View Configuration</a></li>
                        <li><a href="/cognito/test-connection">Test Connections</a></li>
                        <li><a href="/cognito/login?debug=true">Login with Debug Mode</a></li>
                    </ul>
                </body>
            </html>
        `);
    }

    @Get('callback')
    async callback(@Req() req: Request, @Res() res: Response) {
        try {
            Logger.info(`Received callback from Cognito`, 'CognitoAuthController');
            Logger.info(`Query parameters: ${JSON.stringify(req.query)}`, 'CognitoAuthController');
            
            if (req.query.error) {
                Logger.error(`Cognito returned an error: ${req.query.error}`, 'CognitoAuthController');
                if (req.query.error_description) {
                    Logger.error(`Error description: ${req.query.error_description}`, 'CognitoAuthController');
                }
                return res.redirect(`/admin?authError=${encodeURIComponent(req.query.error_description as string || req.query.error as string)}`);
            }
            
            // Log strategy state
            Logger.info(`CognitoAuthStrategy initialization state before callback: ${this.cognitoAuthStrategy['initialized'] ? 'initialized' : 'not initialized'}`, 'CognitoAuthController');
            
            await this.cognitoAuthStrategy.validateCallback(req, res);
        } catch (error) {
            Logger.error(`Callback handling error: ${error instanceof Error ? error.message : String(error)}`, 'CognitoAuthController');
            if (error instanceof Error && error.stack) {
                Logger.error(`Stack trace: ${error.stack}`, 'CognitoAuthController');
            }
            res.redirect('/admin?authError=Authentication process failed');
        }
    }

    @Get('debug')
    async debugInfo(@Res() res: Response) {
        Logger.info('Debug endpoint called', 'CognitoAuthController');
        
        // Get network information to help debug connectivity issues
        const networkInfo: Record<string, any> = {};
        
        // Declare cognitoDomain before using it
        const cognitoDomain = process.env.COGNITO_DOMAIN || '';
        // Declare tokenURL variable here so it's in scope for the entire method
        const tokenURL = `https://${cognitoDomain}/oauth2/token`;
        
        try {
            const { exec } = require('child_process');
            const promiseExec = (cmd: string) => new Promise((resolve) => {
                exec(cmd, (error: any, stdout: string, stderr: string) => {
                    resolve({ error, stdout, stderr });
                });
            });
            
            // Use the already declared cognitoDomain
            networkInfo.dnsLookup = await promiseExec(`dig ${cognitoDomain} +short`);
            
            // Try ping
            networkInfo.ping = await promiseExec(`ping -c 3 ${cognitoDomain}`);
            
            // Use the already declared tokenURL
            networkInfo.curl = await promiseExec(`curl -v -s -o /dev/null -w "%{http_code}" ${tokenURL}`);
        } catch (e) {
            networkInfo.error = e instanceof Error ? e.message : String(e);
        }
        
        // Create a constructed JWKS URL if needed
        const awsRegion = process.env.AWS_REGION || '';
        const userPoolId = process.env.COGNITO_USER_POOL_ID || '';
        const loginUrl = process.env.COGNITO_LOGIN_URL;
        const redirectUri = `${process.env.PUBLIC_URL || 'http://localhost:4002'}/cognito/callback`;
        const constructedJwksUrl = userPoolId ? `https://cognito-idp.${awsRegion}.amazonaws.com/${userPoolId}/.well-known/jwks.json` : '';
        
        const debugInfo = {
            environment: {
                AWS_REGION: process.env.AWS_REGION || 'not set',
                COGNITO_USER_POOL_ID: process.env.COGNITO_USER_POOL_ID || 'not set',
                COGNITO_CLIENT_ID: process.env.COGNITO_CLIENT_ID || 'not set',
                COGNITO_DOMAIN: process.env.COGNITO_DOMAIN || 'not set',
                COGNITO_JWKS_URL: process.env.COGNITO_JWKS_URL || 'not set',
                COGNITO_ISSUER: process.env.COGNITO_ISSUER || 'not set',
                COGNITO_AUDIENCE: process.env.COGNITO_AUDIENCE || 'not set',
                PUBLIC_URL: process.env.PUBLIC_URL || 'not set',
                COGNITO_LOGIN_URL: process.env.COGNITO_LOGIN_URL || 'not set',
            },
            constructedUrls: {
                loginUrl,
                tokenUrl: tokenURL,
                redirectUri,
                constructedJwksUrl,
            },
            strategyStatus: {
                initialized: this.cognitoAuthStrategy['initialized'] || false,
                initError: this.cognitoAuthStrategy['initError'] || null,
                hasJwksClient: !!this.cognitoAuthStrategy['jwksClient']
            },
            networkTests: networkInfo
        };
        
        Logger.info(`Debug info: ${JSON.stringify(debugInfo, null, 2)}`, 'CognitoAuthController');
        
        // Send as formatted HTML for easier reading
        return res.send(`
            <html>
                <head>
                    <title>Cognito Debug Info</title>
                    <style>
                        body { font-family: monospace; padding: 20px; }
                        pre { background: #f5f5f5; padding: 15px; border-radius: 5px; }
                        h1, h2 { font-family: Arial, sans-serif; }
                    </style>
                </head>
                <body>
                    <h1>Cognito Debug Information</h1>
                    
                    <h2>Environment Variables</h2>
                    <pre>${JSON.stringify(debugInfo.environment, null, 2)}</pre>
                    
                    <h2>Constructed URLs</h2>
                    <pre>${JSON.stringify(debugInfo.constructedUrls, null, 2)}</pre>
                    
                    <h2>Strategy Status</h2>
                    <pre>${JSON.stringify(debugInfo.strategyStatus, null, 2)}</pre>
                    
                    <h2>Network Tests</h2>
                    <pre>${JSON.stringify(debugInfo.networkTests, null, 2)}</pre>
                    
                    <h2>Actions</h2>
                    <ul>
                        <li><a href="/cognito/test-connection">Test connections</a></li>
                        <li><a href="/cognito/login">Try login</a></li>
                        <li><a href="/cognito">Back to main page</a></li>
                    </ul>
                </body>
            </html>
        `);
    }
}
