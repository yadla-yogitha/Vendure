import { ChangeDetectionStrategy, Component, OnInit } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { DataService } from '@vendure/admin-ui/core';

@Component({
    selector: 'vdr-oauth-callback',
    template: `<div class="loading">Processing authentication...</div>`,
    styles: [
        `
            .loading {
                display: flex;
                align-items: center;
                justify-content: center;
                height: 100vh;
                font-size: 1.2rem;
            }
        `,
    ],
    changeDetection: ChangeDetectionStrategy.OnPush,
})
export class OAuthCallbackComponent implements OnInit {
    constructor(
        private route: ActivatedRoute,
        private router: Router,
        private dataService: DataService,
    ) {}

    ngOnInit() {
        this.route.queryParamMap.subscribe(params => {
            const code = params.get('code');
            
            if (!code) {
                this.router.navigate(['/login']);
                return;
            }

            // In a real implementation, you would use this code to get tokens
            // and then authenticate the user with your custom authentication strategy
            
            // For example:
            this.dataService.auth
                .authenticate('cognito', { token: code })
                .subscribe({
                    next: () => this.router.navigate(['/dashboard']),
                    error: err => {
                        console.error('Authentication error:', err);
                        this.router.navigate(['/login']);
                    },
                });
        });
    }
}
