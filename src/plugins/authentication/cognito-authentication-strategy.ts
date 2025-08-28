import {
    AuthenticationStrategy,
    ExternalAuthenticationService,
    Injector,
    Logger,
    RequestContext,
    User,
} from '@vendure/core';
import { DocumentNode } from 'graphql';
import gql from 'graphql-tag';
import { CognitoIdentityProviderClient, GetUserCommand } from '@aws-sdk/client-cognito-identity-provider';

export type CognitoAuthData = {
    token: string;
};

export type CognitoAuthConfig = {
    region: string;
    userPoolId: string;
    clientId: string;
    clientSecret?: string;
    jwksUrl?: string;
    issuer?: string;
    audience?: string;
};

export class CognitoAuthenticationStrategy implements AuthenticationStrategy<CognitoAuthData> {
    readonly name = 'cognito';
    private externalAuthenticationService: ExternalAuthenticationService;
    private cognitoClient: CognitoIdentityProviderClient;

    constructor(private config: CognitoAuthConfig) {
        this.cognitoClient = new CognitoIdentityProviderClient({
            region: config.region,
        });
    }

    init(injector: Injector) {
        this.externalAuthenticationService = injector.get(ExternalAuthenticationService);
    }

    defineInputType(): DocumentNode {
        return gql`
            input CognitoAuthInput {
                token: String!
            }
        `;
    }

    async authenticate(ctx: RequestContext, data: CognitoAuthData): Promise<User | false> {
        try {
            const { token } = data;
            
            // Verify the token with Cognito and get user info
            const command = new GetUserCommand({
                AccessToken: token,
            });
            
            const userResponse = await this.cognitoClient.send(command);
            
            if (!userResponse || !userResponse.Username) {
                return false;
            }
            
            // Extract user attributes
            const getAttributeValue = (name: string) => {
                const attr = userResponse.UserAttributes?.find((a: { Name?: string }) => a.Name === name);
                return attr ? attr.Value : undefined;
            };
            
            const sub = getAttributeValue('sub');
            const email = getAttributeValue('email');
            const givenName = getAttributeValue('given_name') || '';
            const familyName = getAttributeValue('family_name') || '';
            const emailVerified = getAttributeValue('email_verified') === 'true';
            
            if (!sub || !email) {
                Logger.error(`Failed to get required attributes from Cognito user`, 'CognitoAuthStrategy');
                return false;
            }

            // Check if this user has already authenticated with Cognito before
            const existingUser = await this.externalAuthenticationService.findCustomerUser(ctx, this.name, sub);
            if (existingUser) {
                return existingUser;
            }

            // If not found, create a new user
            return this.externalAuthenticationService.createCustomerAndUser(ctx, {
                strategy: this.name,
                externalIdentifier: sub,
                verified: emailVerified,
                emailAddress: email,
                firstName: givenName,
                lastName: familyName,
            });
        } catch (error: unknown) {
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            Logger.error(`Error authenticating with Cognito: ${errorMessage}`, 'CognitoAuthStrategy');
            return false;
        }
    }
}
