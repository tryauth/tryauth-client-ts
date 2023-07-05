# tryauth-client-ts

[![NPM version][npm-image]][npm-url]

## Index

- [Install](#install)
- [Implicit Flow](#implicit-flow)
- [Authorization Code Flow](#authorization-code-flow)
- [Check](#check)

[npm-image]: https://img.shields.io/npm/v/@tryauth/tryauth-client-ts.svg?style=flat-square
[npm-url]: https://www.npmjs.com/package/@tryauth/tryauth-client-ts

## Install

From [npm](https://npmjs.org):

```sh
npm install @tryauth/tryauth-client-ts
```

After installing the `tryauth-client-ts` module using [npm](https://npmjs.org), you'll need to import it using:

```
import TryAuth from '@tryauth/tryauth-client-ts';
```

## Implicit Flow

Provides support for `implicit` authentication flow.

### Initialize

The `Authorize` will redirect to the Issuer Endpoint than the user can login.

```js
const tryAuth: TryAuth = new TryAuth();
tryAuth.Authorize({
    ClientId: '<contact us to get a trial ClientId>',
    IssuerEndpoint: '<contact us to get a trial Issuer Endpoint>',
    ResponseType: 'token id_token', // return id_token and access_token in querystring
    Scopes: 'openid email'
    // RedirectUri: ''  it's not required, window.location it's the default value
});
```

**Parameters**

| Option|Type|Description|
| :---------------------------- | ----------------- | ---------- |
| `ClientId`| string (required) | The Client ID found on your Application settings page.
| `IssuerEndpoint`| string (required) | Your TryAuth account domain such as `'example.tryauth.com'` or `'example.tryauth.com'`.
| `ResponseType`| string (required) | Response type for all authentication requests. Only supports `token id_token`.
| `Scopes`| string (required) | The default scopes used for all authorization requests.
| `RedirectUri` | string | The URL where TryAuth will call back to with the result of a successful or failed authentication.

## Check

Allows to acquire a new token and/or access token for a user who has already authenticated against TryAuth for your domain. If the user is not authenticated, you will receive an error.

```js
const tryAuth: TryAuth = new TryAuth();
const tryAuthAuthorizationResponse = await tryAuth.CheckAuthorize();

console.log('AccessToken=' + tryAuthAuthorizationResponse.AccessToken);
console.log('IdToken=' + tryAuthAuthorizationResponse.IdToken);
console.log('ExpiresAt=' + tryAuthAuthorizationResponse.ExpiresAt);
console.log('Email=' + tryAuthAuthorizationResponse.Email);
console.log('Error=' + tryAuthAuthorizationResponse.Error);
```

## Authorization Code Flow

Provides support for `authorization_code` authentication flow with PKCE (Proof Key for Code Exchange).

### Initialize

The `GetAuthorizationCode` function will redirect to the Issuer Endpoint than the user can login. After login the response callback URL will store the `code` in the browser's local storage.

```js
const tryAuth: TryAuth = new TryAuth();
tryAuth.GetAuthorizationCode({
    ClientId: '<contact us to get a trial ClientId>',
    IssuerEndpoint: '<contact us to get a trial Issuer Endpoint>',
    ResponseType: 'code',
    Scopes: 'openid email profile offline_access',
    // RedirectUri: ''  it's not required, window.location it's the default value
});
```

**Parameters**

| Option|Type|Description|
| :---------------------------- | ----------------- | ---------- |
| `ClientId`| string (required) | The Client ID found on your Application settings page.
| `IssuerEndpoint`| string (required) | Your TryAuth account domain such as `'example.tryauth.com'` or `'example.tryauth.com'`.
| `ResponseType`| string (required) | Response type for all authentication requests. Only supports `code`.
| `Scopes`| string (required) | The default scopes used for all authorization requests. Enable refresh token adding `offline_access` scope.
| `RedirectUri` | string | The URL where TryAuth will call back to with the result of a successful or failed authentication.

### Get Access Token, Id Token and optional Refresh Token code

After you login and the `code` already is stored in the browser's local storage you can get the `access_token`, `id_token`, `refresh_token` (optional, dependes on the `offline_access` scope) using the `GetSilentAuthorizationCodeToken` function.

> The `code` only can be used one time.

```js
const tryAuth: TryAuth = new TryAuth();
const tryAuthAuthorizationCodeTokenResponse = tryAuth.GetSilentAuthorizationCodeToken({
    ClientId: '<contact us to get a trial ClientId>',
    ClientSecret: '<contact us to get a trial ClientSecret>',
    IssuerEndpoint: '<contact us to get a trial Issuer Endpoint>',
    ResponseType: 'code'
});
```

**Parameters**

| Option|Type|Description|
| :---------------------------- | ----------------- | ---------- |
| `ClientId`| string (required) | The Client ID found on your Application settings page.
| `ClientSecret`| string (required) | The Client Secret found on your Application settings page.
| `IssuerEndpoint`| string (required) | Your TryAuth account domain such as `'example.tryauth.com'` or `'example.tryauth.com'`.
| `ResponseType`| string (required) | Response type for all authentication requests. Only supports `code`.

**Return**

The `tryAuthAuthorizationCodeTokenResponse` object contains some properties like:

| Property|
| :---------------------------- |
|AccessToken|
|IdToken|
|RefreshToken|
|TokenType|
|Error|

### Renew the Access Token using Refresh Token

If you choose to receive the Refresh Token using the `offline_access` scope, you can renew your Access Token using the `GetAuthorizationCodeRefreshToken` function.

```js
const tryAuth: TryAuth = new TryAuth();
const tryAuthAuthorizationCodeTokenResponse = tryAuth.GetAuthorizationCodeRefreshToken({
    ClientId: '<contact us to get a trial ClientId>',
    ClientSecret: '<contact us to get a trial ClientSecret>',
    IssuerEndpoint: '<contact us to get a trial Issuer Endpoint>',
    RefreshToken: '<the refresh token code you receive in the function above>'
});
```

**Parameters**

| Option|Type|Description|
| :---------------------------- | ----------------- | ---------- |
| `ClientId`| string (required) | The Client ID found on your Application settings page.
| `ClientSecret`| string (required) | The Client Secret found on your Application settings page.
| `IssuerEndpoint`| string (required) | Your TryAuth account domain such as `'example.tryauth.com'` or `'example.tryauth.com'`.
| `RefreshToken`| string (required) | The refresh token code you receive in the function above.

**Return**

The `tryAuthAuthorizationCodeTokenResponse` object is the same of `GetSilentAuthorizationCodeToken` function above.

### Logout

For logout use the `LogoutEndSessionAuthorizationCode` function.

```js
const tryAuth: TryAuth = new TryAuth();
tryAuth.LogoutEndSessionAuthorizationCode({
    ResponseType: 'code',
    IssuerEndpoint: '<contact us to get a trial Issuer Endpoint>',
    RedirectUri: '<after logout the url return>',
    IdToken: '<id_token>',
    State: 'the state in url'
});
```

**Parameters**

| Option|Type|Description|
| :---------------------------- | ----------------- | ---------- |
| `ResponseType`| string (required) | `code`
| `IssuerEndpoint`| string (required) | Your TryAuth account domain such as `'example.tryauth.com'` or `'example.tryauth.com'`.
| `RedirectUri`| string (required) | After logout TryAuth will redirect to this URL. 
| `IdToken`| string (required) | The `id_token` you receive when you get the token.
| `State`| string (required) | After log in the state will be in the URL.
