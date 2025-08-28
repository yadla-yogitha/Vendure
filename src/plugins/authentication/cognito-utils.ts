import { PluginCommonModule, VendurePlugin } from '@vendure/core';
import { Controller, Get, Req, Res } from '@nestjs/common';
import { Request, Response } from 'express';
import { Logger } from '@vendure/core';

@Controller('cognito')
export class CognitoController {
    constructor() {}

    @Get('callback')
    async handleCallback(@Req() req: Request, @Res() res: Response) {
        // Extract the access token from the query parameters
        // This is where you would handle the OAuth callback from Cognito
        const { code } = req.query;
        
        if (!code) {
            Logger.error('No code provided in Cognito callback', 'CognitoController');
            return res.redirect('/admin?error=auth_failed');
        }
        
        try {
            // In a real implementation, you would exchange the code for tokens
            // using Cognito's OAuth endpoints
            Logger.info(`Received authorization code from Cognito: ${code}`, 'CognitoController');
            
            // For now, we'll just redirect to a page where frontend JS
            // can handle the authentication
            return res.redirect(`/admin/oauth-callback?code=${code}`);
        } catch (error: unknown) {
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            Logger.error(`Error handling Cognito callback: ${errorMessage}`, 'CognitoController');
            return res.redirect('/admin?error=auth_failed');
        }
    }
}

@VendurePlugin({
    imports: [PluginCommonModule],
    controllers: [CognitoController],
})
export class CognitoAuthPlugin {}
