# tryauth-client-ts

[![NPM version][npm-image]][npm-url]

## Index

- [Install](#install)
- [Flow](#flow)
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

## Flow

Provides support for `implicit` authentication flows.

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
| `responseType`| string (required) | Response type for all authentication requests. Only supports `token id_token`.
| `Scopes`| string (required) | The default scopes used for all authorization requests.
| `RedirectUri` | string | The URL where TryAuth will call back to with the result of a successful or failed authentication.

## Check

Allows to acquire a new token and/or access token for a user who has already authenticated aginst TryAuth for your domain. If the user is not authenticated, you will receive an error.

```js
const tryAuth: TryAuth = new TryAuth();
const tryAuthAuthorizationResponse = await tryAuth.CheckAuthorize();

console.log('AccessToken=' + tryAuthAuthorizationResponse.AccessToken);
console.log('IdToken=' + tryAuthAuthorizationResponse.IdToken);
console.log('ExpiresAt=' + tryAuthAuthorizationResponse.ExpiresAt);
console.log('Email=' + tryAuthAuthorizationResponse.Email);
console.log('Error=' + tryAuthAuthorizationResponse.Error);
```