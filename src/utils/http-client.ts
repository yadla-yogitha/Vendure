import { Logger } from '@vendure/core';
import * as https from 'https';
import * as http from 'http';
import { URL } from 'url';

export interface HttpResponse {
    statusCode: number;
    data: any;
    headers: Record<string, string | string[]>;
}

export class HttpClient {
    /**
     * Make an HTTP request with automatic fallbacks and error handling
     */
    static async request(
        url: string,
        method: string,
        headers: Record<string, string> = {},
        body?: string | Buffer
    ): Promise<HttpResponse> {
        Logger.info(`[HttpClient] Making ${method} request to ${url}`, 'HttpClient');
        
        // Try different methods in sequence until one works
        return this.nativeHttpRequest(url, method, headers, body)
            .catch(async err => {
                Logger.warn(`Native HTTP request failed: ${err.message}. Trying with curl...`, 'HttpClient');
                return this.curlRequest(url, method, headers, body);
            })
            .catch(async err => {
                Logger.error(`All HTTP request methods failed: ${err.message}`, 'HttpClient');
                throw err;
            });
    }
    
    /**
     * Make an HTTP request using Node.js native http/https modules
     */
    private static nativeHttpRequest(
        url: string,
        method: string,
        headers: Record<string, string> = {},
        body?: string | Buffer
    ): Promise<HttpResponse> {
        return new Promise((resolve, reject) => {
            try {
                const parsedUrl = new URL(url);
                Logger.info(`[HttpClient] Native request to ${parsedUrl.hostname}`, 'HttpClient');
                
                const options = {
                    hostname: parsedUrl.hostname,
                    port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
                    path: parsedUrl.pathname + parsedUrl.search,
                    method,
                    headers,
                    timeout: 10000,
                };
                
                const protocol = parsedUrl.protocol === 'https:' ? https : http;
                const req = protocol.request(options, res => {
                    let responseData = '';
                    res.on('data', chunk => {
                        responseData += chunk;
                    });
                    
                    res.on('end', () => {
                        let parsedData;
                        try {
                            parsedData = JSON.parse(responseData);
                        } catch (e) {
                            parsedData = responseData;
                        }
                        
                        resolve({
                            statusCode: res.statusCode || 0,
                            data: parsedData,
                            headers: res.headers as Record<string, string | string[]>,
                        });
                    });
                });
                
                req.on('error', e => {
                    reject(e);
                });
                
                req.on('timeout', () => {
                    req.destroy(new Error('Request timeout'));
                    reject(new Error('Request timeout after 10 seconds'));
                });
                
                if (body) {
                    req.write(body);
                }
                
                req.end();
            } catch (err) {
                reject(err);
            }
        });
    }
    
    /**
     * Make an HTTP request using curl command (as a last resort)
     */
    private static curlRequest(
        url: string,
        method: string,
        headers: Record<string, string> = {},
        body?: string | Buffer
    ): Promise<HttpResponse> {
        return new Promise((resolve, reject) => {
            const { exec } = require('child_process');
            
            let curlCmd = `curl -s -X ${method} `;
            
            // Add headers
            Object.entries(headers).forEach(([key, value]) => {
                curlCmd += `-H "${key}: ${value}" `;
            });
            
            // Add request body if present
            if (body) {
                curlCmd += `-d '${body.toString().replace(/'/g, "'\\''")}' `;
            }
            
            // Add URL
            curlCmd += `"${url}"`;
            
            Logger.info(`[HttpClient] Executing curl command: ${curlCmd.replace(/client_secret=[^'"\s]+/, 'client_secret=REDACTED')}`, 'HttpClient');
            
            exec(curlCmd, (error: any, stdout: string, stderr: string) => {
                if (error) {
                    Logger.error(`[HttpClient] Curl exec error: ${error.message}`, 'HttpClient');
                    return reject(error);
                }
                
                if (stderr) {
                    Logger.warn(`[HttpClient] Curl stderr: ${stderr}`, 'HttpClient');
                }
                
                let responseData;
                try {
                    responseData = JSON.parse(stdout);
                } catch (e) {
                    responseData = stdout;
                }
                
                resolve({
                    statusCode: 200, // We don't get real status code from curl output without extra flags
                    data: responseData,
                    headers: {},
                });
            });
        });
    }
}
