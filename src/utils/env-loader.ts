import * as fs from 'fs';
import * as path from 'path';
import { Logger } from '@vendure/core';

/**
 * Loads environment variables from .env file to ensure they're available
 * throughout the application.
 */
export function loadEnvVariables(): void {
    try {
        const envPath = path.join(process.cwd(), '.env');
        Logger.info(`Attempting to load environment variables from: ${envPath}`, 'EnvLoader');
        
        if (fs.existsSync(envPath)) {
            const envContent = fs.readFileSync(envPath, 'utf-8');
            const lines = envContent.split('\n');
            
            let loaded = 0;
            for (const line of lines) {
                // Skip comments and empty lines
                if (!line || line.startsWith('#') || line.startsWith('//')) continue;
                
                // Extract key=value
                const match = line.match(/^\s*([^=]+)\s*=\s*(.*?)\s*$/);
                if (match) {
                    const key = match[1];
                    const value = match[2].replace(/^['"]|['"]$/g, ''); // Remove quotes if present
                    
                    // Only set if not already defined
                    if (!process.env[key]) {
                        process.env[key] = value;
                        loaded++;
                    }
                }
            }
            
            Logger.info(`Loaded ${loaded} environment variables from .env file`, 'EnvLoader');
        } else {
            Logger.warn('.env file not found', 'EnvLoader');
        }
    } catch (error) {
        Logger.error(`Failed to load .env file: ${error instanceof Error ? error.message : String(error)}`, 'EnvLoader');
    }
}
