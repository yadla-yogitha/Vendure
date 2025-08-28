import { NgModule } from '@angular/core';
import { RouterModule } from '@angular/router';
import { SharedModule } from '@vendure/admin-ui/core';
import { LoginPageComponent } from './components/login-page/login-page.component';
import { OAuthCallbackComponent } from './components/oauth-callback/oauth-callback.component';

@NgModule({
    imports: [
        SharedModule,
        RouterModule.forChild([
            {
                path: '',
                pathMatch: 'full',
                component: LoginPageComponent,
                data: { breadcrumb: 'Login' },
            },
            {
                path: 'oauth-callback',
                component: OAuthCallbackComponent,
                data: { breadcrumb: 'OAuth Callback' },
            },
        ]),
    ],
    declarations: [LoginPageComponent, OAuthCallbackComponent],
})
export class LoginExtensionModule {}
