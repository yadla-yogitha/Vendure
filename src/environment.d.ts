export {};

// Here we declare the members of the process.env object, so that we
// can use them in our application code in a type-safe manner.
declare global {
    namespace NodeJS {
        interface ProcessEnv {
            APP_ENV: string;
            PORT: string;
            COOKIE_SECRET: string;
            SUPERADMIN_USERNAME: string;
            SUPERADMIN_PASSWORD: string;
            DB_HOST: string;
            DB_PORT: string;
            DB_NAME: string;
            DB_USERNAME: string;
            DB_PASSWORD: string;
            DB_SCHEMA: string;
            
            // Cognito settings
            AWS_REGION: string;
            COGNITO_USER_POOL_ID: string;
            COGNITO_CLIENT_ID: string;
            COGNITO_DOMAIN: string;
            COGNITO_JWKS_URL: string;
            COGNITO_ISSUER: string;
            COGNITO_AUDIENCE: string;
            COGNITO_LOGIN_URL: string;
            AUTH_ENABLED: string;
            AUTH_PROVIDER: string;
        }
    }
}
