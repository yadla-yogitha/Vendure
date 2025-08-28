import { ChangeDetectionStrategy, Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';
import { DataService } from '@vendure/admin-ui/core';
import gql from 'graphql-tag';

@Component({
    selector: 'vdr-login-page',
    templateUrl: './login-page.component.html',
    styleUrls: ['./login-page.component.scss'],
    changeDetection: ChangeDetectionStrategy.OnPush,
})
export class LoginPageComponent implements OnInit {
    cognitoLoginUrl = '';

    constructor(private dataService: DataService, private router: Router) {}

    ngOnInit() {
        this.dataService.client
            .query(
                gql`
                    query GetGlobalSettings {
                        globalSettings {
                            serverConfig {
                                adminUiConfig {
                                    loginUrl
                                }
                            }
                        }
                    }
                `,
                {},
            )
            .single$.subscribe(data => {
                const loginUrl = data.globalSettings?.serverConfig?.adminUiConfig?.loginUrl;
                if (loginUrl) {
                    // Redirect to Cognito login
                    window.location.href = loginUrl;
                }
            });
    }
}
