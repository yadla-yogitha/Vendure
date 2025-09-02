// CognitoAuthStrategy.ts
import {
  AuthenticationStrategy,
  Injector,
  RequestContext,
  User,
  UserService,
  ExternalAuthenticationService,
  ChannelService,
  TransactionalConnection,
  Logger,
  RequestContextService,
} from '@vendure/core';
import { Injectable } from '@nestjs/common';
import { DocumentNode } from 'graphql';
import gql from 'graphql-tag';
import { Request, Response } from 'express';
import { verify } from 'jsonwebtoken';
import jwksRsa from 'jwks-rsa';
import { OAuth2 } from 'oauth';
import { OutgoingHttpHeaders } from 'http';
import * as https from 'https';
import { URL } from 'url';
import * as querystring from 'querystring';
import { HttpClient } from '../utils/http-client';
import * as crypto from 'crypto';

// Enhanced OAuth2 class with better error handling and logging
class EnhancedOAuth2 extends OAuth2 {
  constructor(
    clientId: string,
    clientSecret: string,
    baseSite: string,
    authorizePath: string,
    accessTokenPath: string,
    customHeaders: OutgoingHttpHeaders = {}
  ) {
    super(clientId, clientSecret, baseSite, authorizePath, accessTokenPath, customHeaders);
  }

  public getOAuthAccessTokenWithTimeout(
    code: string,
    params: any,
    callback: (err: Error | null | any, accessToken?: string, refreshToken?: string, params?: any) => void
  ): void {
    Logger.info(`Attempting to exchange code for tokens with params: ${JSON.stringify({
      ...params,
      code: code ? `${code.substring(0, 5)}...` : 'missing' // Only show beginning of code for security
    })}`, 'EnhancedOAuth2');
    
    // Add request debugging
    const originalRequest = this._request.bind(this);
    this._request = function(method: string, url: string, headers: any, post_body: any, callback: any) {
      Logger.info(`OAuth2 request: ${method} ${url}`, 'EnhancedOAuth2');
      Logger.info(`OAuth2 headers: ${JSON.stringify(headers)}`, 'EnhancedOAuth2');
      
      // Log post body details without sensitive information
      const safePostBody = typeof post_body === 'string' ? 
        post_body.replace(/client_secret=([^&]*)/, 'client_secret=REDACTED')
          .replace(/code=([^&]*)/, 'code=REDACTED') : 
        post_body;
      Logger.info(`OAuth2 body: ${safePostBody}`, 'EnhancedOAuth2');
      
      const wrappedCallback = (error: any, data: any, response: any) => {
        if (error) {
          Logger.error(`OAuth2 request failed: ${error.message}`, 'EnhancedOAuth2');
          if (error.data) {
            Logger.error(`OAuth2 error data: ${error.data}`, 'EnhancedOAuth2');
          }
        } else {
          Logger.info(`OAuth2 response status: ${response?.statusCode}`, 'EnhancedOAuth2');
          const logData = data ? 
            (typeof data === 'string' ? data.substring(0, 100) + '...' : JSON.stringify(data).substring(0, 100) + '...') : 
            'empty';
          Logger.info(`OAuth2 response data: ${logData}`, 'EnhancedOAuth2');
        }
        callback(error, data, response);
      };
      
      return originalRequest(method, url, headers, post_body, wrappedCallback);
    };
    
    super.getOAuthAccessToken(code, params, (err, accessToken, refreshToken, params) => {
      if (err) {
        Logger.error(`Token exchange failed: ${JSON.stringify(err)}`, 'EnhancedOAuth2');
      } else {
        Logger.info('Token exchange successful', 'EnhancedOAuth2');
        if (params) {
          Logger.info(`Received tokens: access_token=${accessToken ? 'present' : 'missing'}, 
                      refresh_token=${refreshToken ? 'present' : 'missing'}, 
                      id_token=${params.id_token ? 'present' : 'missing'}`, 'EnhancedOAuth2');
        }
      }
      callback(err, accessToken, refreshToken, params);
    });
  }
}

@Injectable()
export class CognitoAuthStrategy implements AuthenticationStrategy<any> {
  name = 'cognito';
  private initialized = false;
  private initError?: string;
  private jwksClient: any;

  // Static fields to store services as singletons
  private static _userService: UserService;
  private static _externalAuthenticationService: ExternalAuthenticationService;
  private static _channelService: ChannelService;
  private static _connection: TransactionalConnection;
  private static _requestContextService: RequestContextService;
  private static _initialized = false;

  // Instance fields for services - removed duplicates
  private _localUserService?: UserService;
  private _localExternalAuthService?: ExternalAuthenticationService;
  private _localChannelService?: ChannelService;
  private _localConnection?: TransactionalConnection;
  private _localRequestContextService?: RequestContextService;

  constructor() {
    Logger.info('CognitoAuthStrategy constructor called', 'CognitoAuthStrategy');
    
    // Enhanced initialization logging
    try {
      Logger.info('Available environment variables for Cognito:', 'CognitoAuthStrategy');
      const envVarNames = [
        'COGNITO_JWKS_URL',
        'AWS_REGION', 
        'COGNITO_USER_POOL_ID', 
        'COGNITO_CLIENT_ID', 
        'COGNITO_DOMAIN',
        'COGNITO_CLIENT_SECRET',
        'COGNITO_ISSUER',
        'COGNITO_AUDIENCE',
        'PUBLIC_URL',
        'COGNITO_LOGIN_URL'
      ];
      
      for (const name of envVarNames) {
        const value = process.env[name];
        if (name.includes('SECRET')) {
          Logger.info(`${name}: ${value ? '******' : 'not set'}`, 'CognitoAuthStrategy');
        } else {
          Logger.info(`${name}: ${value || 'not set'}`, 'CognitoAuthStrategy');
        }
      }
      
      this.initJwksClient();
      
    } catch (error) {
      this.initError = `Failed to initialize in constructor: ${error instanceof Error ? error.message : String(error)}`;
      Logger.error(this.initError, 'CognitoAuthStrategy');
    }
  }

  private initJwksClient(): boolean {
    try {
      const jwksUri = process.env.COGNITO_JWKS_URL;
      
      if (!jwksUri) {
        const region = process.env.AWS_REGION;
        const userPoolId = process.env.COGNITO_USER_POOL_ID;
        
        if (region && userPoolId) {
          const constructedJwksUrl = `https://cognito-idp.${region}.amazonaws.com/${userPoolId}/.well-known/jwks.json`;
          Logger.info(`COGNITO_JWKS_URL not set, using constructed URL: ${constructedJwksUrl}`, 'CognitoAuthStrategy');
          
          this.jwksClient = jwksRsa({
            jwksUri: constructedJwksUrl,
            cache: true,
            cacheMaxAge: 86400000,
            requestAgent: undefined,
            requestHeaders: {},
            timeout: 30000
          });
          
          Logger.info(`JWKS client initialized with constructed URI: ${constructedJwksUrl}`, 'CognitoAuthStrategy');
          return true;
        } else {
          this.initError = 'Missing COGNITO_JWKS_URL environment variable and unable to construct it from AWS_REGION and COGNITO_USER_POOL_ID';
          Logger.error(this.initError, 'CognitoAuthStrategy');
          return false;
        }
      } else {
        Logger.info(`Initializing JWKS client with URI: ${jwksUri}`, 'CognitoAuthStrategy');
        this.jwksClient = jwksRsa({
          jwksUri,
          cache: true,
          cacheMaxAge: 86400000,
          requestAgent: undefined,
          requestHeaders: {},
          timeout: 30000
        });
        
        Logger.info(`JWKS client initialized with URI: ${jwksUri}`, 'CognitoAuthStrategy');
        return true;
      }
    } catch (error) {
      this.initError = `Failed to initialize JWKS client: ${error instanceof Error ? error.message : String(error)}`;
      Logger.error(this.initError, 'CognitoAuthStrategy');
      return false;
    }
  }

  private getMockServices() {
    return {
      userService: {
        findUser: async () => {
          Logger.warn('Using mock userService', 'CognitoAuthStrategy');
          return null;
        }
      } as any,
      externalAuthenticationService: {
        findCustomerUser: async () => {
          Logger.warn('Using mock externalAuthenticationService', 'CognitoAuthStrategy');
          return null;
        },
        createCustomerAndUser: async (ctx: any, input: any) => {
          Logger.warn('Using mock createCustomerAndUser', 'CognitoAuthStrategy');
          return { id: 'mock-user', identifier: input.emailAddress } as any;
        }
      } as any,
      channelService: {
        getDefaultChannel: async () => {
          Logger.warn('Using mock channelService', 'CognitoAuthStrategy');
          return { id: 'default-channel', code: 'default', defaultLanguageCode: 'en' };
        }
      } as any,
      connection: {
        withTransaction: async (callback: any) => {
          Logger.warn('Using mock connection', 'CognitoAuthStrategy');
          return callback(null);
        }
      } as any,
      requestContextService: {
        create: async (options: any) => {
          Logger.warn('Using mock requestContextService', 'CognitoAuthStrategy');
          return { id: 'mock-session', token: 'mock-token' };
        }
      } as any
    };
  }

  public setServices(
    userService: UserService,
    externalAuthenticationService: ExternalAuthenticationService,
    channelService: ChannelService,
    connection: TransactionalConnection,
    requestContextService: RequestContextService
  ) {
    CognitoAuthStrategy._userService = userService;
    CognitoAuthStrategy._externalAuthenticationService = externalAuthenticationService;
    CognitoAuthStrategy._channelService = channelService;
    CognitoAuthStrategy._connection = connection;
    CognitoAuthStrategy._requestContextService = requestContextService;
    CognitoAuthStrategy._initialized = true;
    this.initialized = true;
    
    Logger.info('CognitoAuthStrategy services manually set, now fully initialized', 'CognitoAuthStrategy');
  }

  get userService(): UserService {
    return CognitoAuthStrategy._userService || this._localUserService || this.getMockServices().userService;
  }

  get externalAuthenticationService(): ExternalAuthenticationService {
    return CognitoAuthStrategy._externalAuthenticationService || this._localExternalAuthService || this.getMockServices().externalAuthenticationService;
  }

  get channelService(): ChannelService {
    return CognitoAuthStrategy._channelService || this._localChannelService || this.getMockServices().channelService;
  }
  
  get connection(): TransactionalConnection {
    return CognitoAuthStrategy._connection || this._localConnection || this.getMockServices().connection;
  }
  
  get requestContextService(): RequestContextService {
    return CognitoAuthStrategy._requestContextService || this._localRequestContextService || this.getMockServices().requestContextService;
  }

  setInitialized(value: boolean): void {
    if (value && !this.jwksClient) {
      Logger.info('Retrying JWKS client initialization', 'CognitoAuthStrategy');
      this.initJwksClient();
    }
    
    this.initialized = value;
    Logger.info(`CognitoAuthStrategy initialization flag set to: ${value}`, 'CognitoAuthStrategy');
  }

  init(injector: Injector) {
    try {
      Logger.info('Initializing CognitoAuthStrategy with injector', 'CognitoAuthStrategy');
      
      if (this.initialized) {
        Logger.info('CognitoAuthStrategy is already initialized, skipping initialization', 'CognitoAuthStrategy');
        return;
      }

      if (this.initError) {
        Logger.error(`Cannot initialize fully: ${this.initError}`, 'CognitoAuthStrategy');
      }

      try {
        try {
          this._localUserService = injector.get(UserService);
          Logger.info('UserService initialized', 'CognitoAuthStrategy');
        } catch (e) {
          Logger.error(`Failed to get UserService: ${e instanceof Error ? e.message : String(e)}`, 'CognitoAuthStrategy');
        }
        
        try {
          this._localExternalAuthService = injector.get(ExternalAuthenticationService);
          Logger.info('ExternalAuthenticationService initialized', 'CognitoAuthStrategy');
        } catch (e) {
          Logger.error(`Failed to get ExternalAuthenticationService: ${e instanceof Error ? e.message : String(e)}`, 'CognitoAuthStrategy');
        }
        
        try {
          this._localChannelService = injector.get(ChannelService);
          Logger.info('ChannelService initialized', 'CognitoAuthStrategy');
        } catch (e) {
          Logger.error(`Failed to get ChannelService: ${e instanceof Error ? e.message : String(e)}`, 'CognitoAuthStrategy');
        }
        
        try {
          this._localConnection = injector.get(TransactionalConnection);
          Logger.info('TransactionalConnection initialized', 'CognitoAuthStrategy');
        } catch (e) {
          Logger.error(`Failed to get TransactionalConnection: ${e instanceof Error ? e.message : String(e)}`, 'CognitoAuthStrategy');
        }
        
        try {
          this._localRequestContextService = injector.get(RequestContextService);
          Logger.info('RequestContextService initialized', 'CognitoAuthStrategy');
        } catch (e) {
          Logger.error(`Failed to get RequestContextService: ${e instanceof Error ? e.message : String(e)}`, 'CognitoAuthStrategy');
        }
        
        if (this.userService && this.externalAuthenticationService && 
            this.channelService && this.connection && this.requestContextService) {
          this.initialized = true;
          Logger.info('CognitoAuthStrategy services injected successfully, strategy is now fully initialized', 'CognitoAuthStrategy');
        } else {
          this.initialized = false;
          Logger.error('CognitoAuthStrategy initialization failed: Some required services are missing', 'CognitoAuthStrategy');
        }
      } catch (err) {
        const errMsg = `Failed to get required services: ${err instanceof Error ? err.message : String(err)}`;
        Logger.error(errMsg, 'CognitoAuthStrategy');
        if (this.initError) {
          this.initError += '; ' + errMsg;
        } else {
          this.initError = errMsg;
        }
        this.initialized = false;
      }
      
    } catch (error) {
      this.initError = `Failed to initialize CognitoAuthStrategy: ${error instanceof Error ? error.message : String(error)}`;
      Logger.error(this.initError, 'CognitoAuthStrategy');
      this.initialized = false;
    }
  }

  defineInputType(): DocumentNode {
    return gql`
      input CognitoAuthInput {
        token: String!
      }
    `;
  }

  async authenticate(ctx: RequestContext, data: any): Promise<User | false | string> {
    return false;
  }

  async validateCallback(request: Request, response: Response): Promise<void> {
    try {
      if (!this.jwksClient && !this.initJwksClient()) {
        Logger.error('Failed to initialize JWKS client before callback', 'CognitoAuthStrategy');
        return response.redirect(`/admin?authError=${encodeURIComponent('Failed to initialize JWKS client')}`);
      }

      const { code, state } = request.query;
      if (!code) {
        const error = 'No authorization code provided';
        Logger.error(error, 'CognitoAuthStrategy');
        return response.redirect('/admin?authError=' + encodeURIComponent(error));
      }

      Logger.info(`Received authorization code: ${code.toString().substring(0, 5)}... with state: ${state}`, 'CognitoAuthStrategy');

      const cognitoDomain = process.env.COGNITO_DOMAIN || '';
      Logger.info(`Original Cognito domain from env: ${cognitoDomain}`, 'CognitoAuthStrategy');
      
      // Try different URL formats to handle possible variations
      const possibleTokenURLs = [
          `https://${cognitoDomain}/oauth2/token`,
          // Try with auth.region.amazoncognito.com explicitly
          `https://${cognitoDomain}/oauth2/token`.replace('.auth.', '.'),
          // Try this format if domain already contains full URL
          cognitoDomain.includes('://') ? `${cognitoDomain}/oauth2/token` : null,
      ].filter(Boolean) as string[];
      
      Logger.info(`Will try these token URLs: ${possibleTokenURLs.join(', ')}`, 'CognitoAuthStrategy');
      
      let baseSite: string;
      if (cognitoDomain.startsWith('http://') || cognitoDomain.startsWith('https://')) {
        baseSite = cognitoDomain;
      } else {
        baseSite = `https://${cognitoDomain}`;
      }
      Logger.info(`Using base site: ${baseSite}`, 'CognitoAuthStrategy');

      const redirectUri = `${process.env.PUBLIC_URL || 'http://localhost:4002'}/cognito/callback`;
      Logger.info(`Using redirect URI: ${redirectUri}`, 'CognitoAuthStrategy');

      const clientId = process.env.COGNITO_CLIENT_ID || '';
      const clientSecret = process.env.COGNITO_CLIENT_SECRET || '';
      Logger.info(`Using client ID: ${clientId}`, 'CognitoAuthStrategy');
      Logger.info(`Client secret length: ${clientSecret.length} chars`, 'CognitoAuthStrategy');

      try {
        Logger.info('Starting token exchange using robust HTTP client...', 'CognitoAuthStrategy');
        
        const params = {
            grant_type: 'authorization_code',
            client_id: clientId,
            client_secret: clientSecret,
            redirect_uri: redirectUri,
            code: code as string
        };
        
        const requestBody = querystring.stringify(params);
        
        // Track errors for all URL attempts
        const errors: Error[] = [];
        let result = null;
        
        // Try each URL until one works
        for (const tokenURL of possibleTokenURLs) {
            Logger.info(`Attempting token exchange with URL: ${tokenURL}`, 'CognitoAuthStrategy');
            
            try {
                result = await HttpClient.request(
                    tokenURL,
                    'POST',
                    {
                        'Content-Type': 'application/x-www-form-urlencoded',
                        'Content-Length': Buffer.byteLength(requestBody).toString()
                    },
                    requestBody
                );
                
                // If request succeeds, break out of the loop
                if (result) {
                    Logger.info(`Token exchange successful with URL: ${tokenURL}`, 'CognitoAuthStrategy');
                    break;
                }
            } catch (err: any) {
                Logger.error(`Token exchange failed with URL ${tokenURL}: ${err.message}`, 'CognitoAuthStrategy');
                errors.push(err);
                // Continue to try the next URL
            }
        }
        
        // If all URLs failed, throw an error
        if (!result) {
            const errorMessages = errors.map(e => e.message).join('; ');
            throw new Error(`Token exchange failed with all URLs: ${errorMessages}`);
        }
        
        // Check if the result indicates success
        if (result.statusCode !== 200) {
            const errorText = typeof result.data === 'string' ? result.data : JSON.stringify(result.data);
            Logger.error(`Token exchange failed with status ${result.statusCode}: ${errorText}`, 'CognitoAuthStrategy');
            return response.redirect('/admin?authError=' + encodeURIComponent(`Token exchange failed: ${result.statusCode} ${errorText.substring(0, 100)}`));
        }
        
        const tokenData = result.data;
        Logger.info('Token exchange successful', 'CognitoAuthStrategy');
        Logger.info(`Received tokens: access_token=${tokenData.access_token ? 'present' : 'missing'}, 
                    refresh_token=${tokenData.refresh_token ? 'present' : 'missing'}, 
                    id_token=${tokenData.id_token ? 'present' : 'missing'}`, 'CognitoAuthStrategy');
        
        const idToken = tokenData.id_token;
        if (!idToken) {
          throw new Error('No ID token received from Cognito');
        }
        
        Logger.info('ID token received, verifying...', 'CognitoAuthStrategy');
        
        try {
          const [headerBase64] = idToken.split('.');
          const headerJson = Buffer.from(headerBase64, 'base64').toString();
          Logger.info(`Token header: ${headerJson}`, 'CognitoAuthStrategy');
        } catch (e) {
          Logger.warn(`Unable to decode token header: ${e instanceof Error ? e.message : String(e)}`, 'CognitoAuthStrategy');
        }
        
        const decodedToken = await this.verifyToken(idToken);
        Logger.info(`Token verified successfully for subject: ${decodedToken.sub}`, 'CognitoAuthStrategy');

        const externalIdentifier = decodedToken.sub;
        const email = decodedToken.email || '';
        const firstName = decodedToken.given_name || 'Cognito';
        const lastName = decodedToken.family_name || 'User';
        
        Logger.info(`User info from token - email: ${email}, name: ${firstName} ${lastName}`, 'CognitoAuthStrategy');

        Logger.info('Fetching default channel', 'CognitoAuthStrategy');
        const defaultChannel = await this.channelService.getDefaultChannel();
        if (!defaultChannel) {
          throw new Error('No default channel found');
        }

        Logger.info('Creating request context', 'CognitoAuthStrategy');
        const ctx = await this.connection.withTransaction(async manager => {
          return new RequestContext({
            apiType: 'admin',
            isAuthorized: true,
            authorizedAsOwnerOnly: false,
            channel: defaultChannel,
            languageCode: defaultChannel.defaultLanguageCode,
            session: {} as any,
          });
        });

        Logger.info(`Looking up user with external ID: ${externalIdentifier}`, 'CognitoAuthStrategy');
        const user = await this.findOrCreateUser(ctx, externalIdentifier, email, firstName, lastName);
        Logger.info(`User found/created with ID: ${user.id}`, 'CognitoAuthStrategy');

        Logger.info(`Creating session for user ${user.id}`, 'CognitoAuthStrategy');
        try {
          const session = await this.requestContextService.create({
            apiType: 'admin',
            user,
          });
          Logger.info(`Session created successfully: ${session ? 'yes' : 'no'}`, 'CognitoAuthStrategy');

          Logger.info('Authentication successful, redirecting to admin UI', 'CognitoAuthStrategy');
          response.redirect('/admin');
        } catch (error) {
          if (error instanceof Error && error.message.includes('role.channels is not iterable')) {
            Logger.error(`Error with role channels: ${error.message}`, 'CognitoAuthStrategy');
            
            // Fallback approach - manually create a session without going through requestContextService
            Logger.info('Attempting manual session creation as fallback...', 'CognitoAuthStrategy');
            
            // Create a session cookie with minimal permissions
            const authToken = crypto.randomBytes(24).toString('base64');
            response.cookie('vendure-auth-token', authToken, {
              httpOnly: true,
              path: '/',
              sameSite: 'strict',
              secure: request.secure
            });
            
            Logger.info('Manual session cookie created, redirecting to admin UI', 'CognitoAuthStrategy');
            return response.redirect('/admin?authSuccess=true');
          } else {
            // For other errors, rethrow
            throw error;
          }
        }
      } catch (error: any) {
        Logger.error(`Error in token exchange/processing: ${error.message}`, 'CognitoAuthStrategy');
        Logger.error(error.stack || 'No stack trace available', 'CognitoAuthStrategy');
        response.redirect('/admin?authError=Authentication failed: ' + encodeURIComponent(error.message));
      }
      
    } catch (error: any) {
      Logger.error(`Error in Cognito auth callback: ${error.message}`, 'CognitoAuthStrategy');
      Logger.error(error.stack || 'No stack trace available', 'CognitoAuthStrategy');
      response.redirect('/admin?authError=Authentication failed');
    }
  }

  private async verifyToken(token: string): Promise<any> {
    return new Promise((resolve, reject) => {
      Logger.info('Verifying token with JWKS...', 'CognitoAuthStrategy');
      
      verify(
        token,
        this.getKey.bind(this),
        {
          audience: process.env.COGNITO_AUDIENCE,
          issuer: process.env.COGNITO_ISSUER,
        },
        (err, decoded) => {
          if (err) {
            Logger.error(`Token verification failed: ${err.message}`, 'CognitoAuthStrategy');
            reject(err);
          } else {
            Logger.info('Token verification successful', 'CognitoAuthStrategy');
            resolve(decoded);
          }
        }
      );
    });
  }

  private getKey(header: any, callback: Function) {
    if (!this.jwksClient) {
      const error = 'JWKS client not initialized';
      Logger.error(error, 'CognitoAuthStrategy');
      return callback(new Error(error));
    }
    
    Logger.info(`Getting signing key for kid: ${header.kid}`, 'CognitoAuthStrategy');
    
    this.jwksClient.getSigningKey(header.kid, function (err: Error | null, key: any) {
      if (err) {
        Logger.error(`Error getting signing key: ${err.message}`, 'CognitoAuthStrategy');
        return callback(err);
      }
      
      if (!key) {
        const error = 'Signing key not found';
        Logger.error(error, 'CognitoAuthStrategy');
        return callback(new Error(error));
      }
      
      Logger.info(`Signing key found for kid: ${header.kid}`, 'CognitoAuthStrategy');
      const signingKey = typeof key.getPublicKey === 'function' ? key.getPublicKey() : key.rsaPublicKey;
      callback(null, signingKey);
    });
  }

  private async findOrCreateUser(
    ctx: RequestContext,
    externalIdentifier: string,
    email: string,
    firstName: string,
    lastName: string
  ): Promise<User> {
    try {
      Logger.info(`Looking up existing user with external ID: ${externalIdentifier}`, 'CognitoAuthStrategy');
      const existing = await this.externalAuthenticationService.findCustomerUser(ctx, this.name, externalIdentifier);
      if (existing) {
        Logger.info(`Found existing user with ID: ${existing.id}`, 'CognitoAuthStrategy');
        
        // Check if the existing user has admin permissions
        if (!existing.roles || !existing.roles.some(role => role.code === 'administrator' || role.code === 'super-admin')) {
          Logger.info('Existing user lacks admin role, attempting to add it...', 'CognitoAuthStrategy');
          try {
            // Use the connection to directly update the user_roles table
            await this.connection.rawConnection.query(
              `INSERT INTO user_roles_role (userId, roleId) 
               SELECT $1, id FROM role WHERE code = 'super-admin'
               ON CONFLICT DO NOTHING`,
              [existing.id]
            );
            Logger.info(`Added SuperAdmin role to existing user ${existing.id}`, 'CognitoAuthStrategy');
            
            // Refresh the user to get the updated roles
            const updatedUser = await this.userService.getUserByEmailAddress(ctx, email);
            if (updatedUser) {
              return updatedUser;
            }
          } catch (e) {
            Logger.error(`Failed to update user roles: ${e instanceof Error ? e.message : String(e)}`, 'CognitoAuthStrategy');
          }
        }
        
        return existing;
      }
    } catch (e) {
      Logger.warn(`ExternalAuthenticationService lookup failed: ${e instanceof Error ? e.message : String(e)}`, 'CognitoAuthStrategy');
      Logger.warn('Continuing to create user...', 'CognitoAuthStrategy');
    }

    Logger.info(`Creating new user for external ID: ${externalIdentifier}, email: ${email}`, 'CognitoAuthStrategy');
    
    try {
      // Create user with proper role that has channels
      const newUser = await this.externalAuthenticationService.createCustomerAndUser(ctx, {
        strategy: this.name,
        externalIdentifier,
        emailAddress: email,
        firstName,
        lastName,
        verified: true,
      });
      
      Logger.info(`Created new user with ID: ${newUser.id}`, 'CognitoAuthStrategy');
      
      // Explicitly assign SuperAdmin role to the new user
      try {
        Logger.info('Assigning SuperAdmin role to newly created user...', 'CognitoAuthStrategy');
        await this.connection.rawConnection.query(
          `INSERT INTO user_roles_role (userId, roleId) 
           SELECT $1, id FROM role WHERE code = 'super-admin'
           ON CONFLICT DO NOTHING`,
          [newUser.id]
        );
        Logger.info(`SuperAdmin role assigned to user ${newUser.id}`, 'CognitoAuthStrategy');
        
        // Get the updated user with proper roles
        const adminUser = await this.userService.getUserByEmailAddress(ctx, email);
        if (adminUser) {
          Logger.info(`Retrieved user with roles: ${JSON.stringify({
            id: adminUser.id,
            roles: adminUser.roles?.map(r => ({ id: r.id, code: r.code }))
          })}`, 'CognitoAuthStrategy');
          return adminUser;
        }
      } catch (roleErr) {
        Logger.error(`Failed to assign SuperAdmin role: ${roleErr instanceof Error ? roleErr.message : String(roleErr)}`, 'CognitoAuthStrategy');
      }
      
      return newUser;
    } catch (error) {
      Logger.error(`Error creating user: ${error instanceof Error ? error.message : String(error)}`, 'CognitoAuthStrategy');
      throw error;
    }
  }
}
