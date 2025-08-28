import { compileUiExtensions } from '@vendure/ui-devkit/compiler';
import path from 'path';

/**
 * This script compiles the admin-ui extensions and makes them
 * available to the Admin UI app.
 */
compileUiExtensions({
    outputPath: path.join(__dirname, '../admin-ui'),
    extensions: [
        {
            // This will replace the default login view with our custom page
            // that redirects to Cognito
            extensionPath: path.join(__dirname, 'login-extension'),
            ngModules: [
                {
                    type: 'lazy',
                    route: 'login',
                    ngModuleFileName: 'login-extension.module.ts',
                    ngModuleName: 'LoginExtensionModule',
                },
            ],
        },
    ],
})
.catch(e => {
    console.error(e);
    process.exit(1);
});
