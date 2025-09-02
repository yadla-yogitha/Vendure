import { PluginCommonModule, VendurePlugin, Logger, EventBus } from '@vendure/core';
import { CognitoAuthStrategy } from './cognito-auth-strategy';
import { CognitoAuthController } from './cognito-auth-controller';
import { Injectable, OnModuleInit } from '@nestjs/common';
import { loadEnvVariables } from '../utils/env-loader';
import { UserService, ExternalAuthenticationService, ChannelService, TransactionalConnection, RequestContextService } from '@vendure/core';

// Load environment variables before creating strategy
loadEnvVariables();

// Log loaded environment variables relevant to Cognito
const envVars = [
    'AWS_REGION', 
    'COGNITO_USER_POOL_ID', 
    'COGNITO_CLIENT_ID', 
    'COGNITO_DOMAIN',
    'COGNITO_CLIENT_SECRET',
    'COGNITO_ISSUER',
    'COGNITO_AUDIENCE',
    'PUBLIC_URL',
    'COGNITO_JWKS_URL',
    'COGNITO_LOGIN_URL'
];

Logger.info('Cognito environment variables:', 'CognitoAuthPlugin');
for (const name of envVars) {
    const value = process.env[name];
    if (name.includes('SECRET')) {
        Logger.info(`${name}: ${value ? '******' : 'not set'}`, 'CognitoAuthPlugin');
    } else {
        Logger.info(`${name}: ${value || 'not set'}`, 'CognitoAuthPlugin');
    }
}

// Create a single instance to be used throughout the application
const cognitoStrategy = new CognitoAuthStrategy();

// Bootstrap service with direct service injection
@Injectable()
class CognitoInitService implements OnModuleInit {
    constructor(
        private eventBus: EventBus,
        private userService: UserService,
        private externalAuthenticationService: ExternalAuthenticationService,
        private channelService: ChannelService,
        private connection: TransactionalConnection,
        private requestContextService: RequestContextService
    ) {}

    async onModuleInit() {
        Logger.info('CognitoInitService initialized with all required services', 'CognitoAuthPlugin');
        
        // Directly set all required services on the strategy
        cognitoStrategy.setServices(
            this.userService,
            this.externalAuthenticationService,
            this.channelService,
            this.connection,
            this.requestContextService
        );
        
        Logger.info('CognitoAuthStrategy fully initialized with injected services', 'CognitoAuthPlugin');
    }
}

@VendurePlugin({
    imports: [PluginCommonModule],
    controllers: [CognitoAuthController],
    providers: [
        {
            provide: CognitoAuthStrategy,
            useValue: cognitoStrategy // Use the pre-created instance directly
        },
        CognitoInitService
    ],
    configuration: config => {
        // Only register the strategy if auth is enabled and provider is cognito
        if (process.env.AUTH_ENABLED === 'true' && process.env.AUTH_PROVIDER === 'cognito') {
            Logger.info('Registering CognitoAuthStrategy with Vendure', 'CognitoAuthPlugin');
            
            // Make sure these arrays exist before attempting to modify them
            config.authOptions.shopAuthenticationStrategy = config.authOptions.shopAuthenticationStrategy || [];
            config.authOptions.adminAuthenticationStrategy = config.authOptions.adminAuthenticationStrategy || [];
            
            // Add the shared strategy instance
            config.authOptions.shopAuthenticationStrategy.push(cognitoStrategy);
            config.authOptions.adminAuthenticationStrategy.push(cognitoStrategy);
            
            Logger.info('CognitoAuthStrategy registered successfully', 'CognitoAuthPlugin');
        } else {
            Logger.warn('CognitoAuthStrategy not registered - check AUTH_ENABLED and AUTH_PROVIDER environment variables', 'CognitoAuthPlugin');
        }
        
        return config;
    }
})
export class CognitoAuthPlugin {}
