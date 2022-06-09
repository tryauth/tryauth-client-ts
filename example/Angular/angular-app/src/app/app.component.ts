import { Component } from '@angular/core';

import TryAuth from '@tryauth/tryauth-client-ts';

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css']
})
export class AppComponent {

  constructor() { }

  ngOnInit() {

  }

  login() {
    this.configureAuth();
  }

  configureAuth() {
    const tryAuth: TryAuth = new TryAuth();
    tryAuth.Authorize({
      ClientId: 'b41647d2091245fea233a7afd4267f9d',
      IssuerEndpoint: 'http://localhost:9990',
      ResponseType: 'token id_token', // return id_token and access_token in querystring
      Scopes: 'openid email'
      // RedirectUri: ''  it's not required, window.location it's the default value
    });
  }

  async check(): Promise<void> {
    const tryAuth: TryAuth = new TryAuth();
    const tryAuthAuthorizationResponse = await tryAuth.CheckAuthorize();

    console.log('AccessToken=' + tryAuthAuthorizationResponse.AccessToken);
    console.log('IdToken=' + tryAuthAuthorizationResponse.IdToken);
    console.log('ExpiresAt=' + tryAuthAuthorizationResponse.ExpiresAt);
    console.log('Email=' + tryAuthAuthorizationResponse.Email);
    console.log('Error=' + tryAuthAuthorizationResponse.Error);
  }
}
