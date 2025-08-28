import {
    AuthenticationStrategy,
    ExternalAuthenticationService,
    Injector,
    Logger,
    RequestContext,
    RoleService,
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
    adminGroupName?: string; // Cognito group for admins
    jwksUrl?: string;
    issuer?: string;
    audience?: string;
};

export class CognitoAdminAuthenticationStrategy implements AuthenticationStrategy<CognitoAuthData> {
    readonly name = 'cognito';
    private externalAuthenticationService: ExternalAuthenticationService;
    private roleService: RoleService;
    private cognitoClient: CognitoIdentityProviderClient;

    constructor(private config: CognitoAuthConfig) {
        this.cognitoClient = new CognitoIdentityProviderClient({
            region: config.region,
        });
    }

    init(injector: Injector) {
        this.externalAuthenticationService = injector.get(ExternalAuthenticationService);
        this.roleService = injector.get(RoleService);
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
            
            if (!sub || !email) {
                Logger.error(`Failed to get required attributes from Cognito user`, 'CognitoAdminAuthStrategy');
                return false;
            }

            // Check if user is already registered
            const existingUser = await this.externalAuthenticationService.findAdministratorUser(ctx, this.name, sub);
            if (existingUser) {
                return existingUser;
            }

            // If not found, we need to create a new admin user
            // First, fetch the appropriate roles
            const roles = await this.roleService.findAll(ctx);
            // Use SuperAdmin or another role as needed
            const adminRole = roles.items.find(r => r.code === 'administrator');

            if (!adminRole) {
                Logger.error(`Could not find administrator role`, 'CognitoAdminAuthStrategy');
                return false;
            }

            return this.externalAuthenticationService.createAdministratorAndUser(ctx, {
                strategy: this.name,
                externalIdentifier: sub,
                identifier: email,
                emailAddress: email,
                firstName: givenName,
                lastName: familyName,
                roles: [adminRole],
            });
        } catch (error: unknown) {
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            Logger.error(`Error authenticating with Cognito: ${errorMessage}`, 'CognitoAdminAuthStrategy');
            return false;
        }
    }
}
