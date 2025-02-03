import JwtDecode from 'jwt-decode';

export class TryAuthAuthorizationResponse {
    public AccessToken: string = null;
    public IdToken: string = null;
    public Email: string = null;
    public ExpiresAt: number = null;
    public Error: TryAuthError = null;
}

export class TryAuthAuthorizationCodeTokenResponse {
    public AccessToken: string = null;
    public IdToken: string = null;
    public RefreshToken: string = null;
    public TokenType: string = null;
    public ExpiresIn: number = null;
    public Error: TryAuthError = null;
}

export class TryAuthAuthorizationCodeResponse {
    public Code: string = null;
    public Scope: string = null;
    public State: string = null;
}

export class TryAuthPkceCode {
    public CodeVerifier: string = null;
    public CodeChallenge: string = null;
}

class TryAuthAuthorizationOptions {
    public ClientId?: string = null;
    public ClientSecret?: string = null;
    public IssuerEndpoint: string = null;
    public RedirectUri?: string = null;
    public ResponseType?: string = null;
    public Scopes?: string = null;
    public CodeChallenge?: string = null;
    public IdToken?: string = null;
    public State?: string = null;
    public RefreshToken?: string = null;
    public ExternalIssuerEndpoint?: string = null;
    public ExternalClientId?: string = null;
    public RequirePkce?: boolean = false;
}

export class TryAuthError {
    public error: string = null;
}

interface JwtPayload {
    iss?: string;
    sub?: string;
    aud?: string[] | string;
    nonce?: string;
    exp?: number;
    nbf?: number;
    iat?: number;
    email?: string;
}

export default class TryAuth {
    private readonly NONCE_KEY = 'tryauth_authorization_nonce_key';
    private readonly REPONSE_URL_KEY = 'tryauth_response_url_key';
    private readonly RESPONSE_TYPE_IDTOKEN_TOKEN: string = 'id_token token';
    private readonly RESPONSE_TYPE_TOKEN_IDTOKEN: string = 'token id_token';
    private readonly RESPONSE_TYPE_CODE: string = 'code';
    private readonly GRANT_TYPE: string = 'grant_type';
    private readonly AUTHORIZATION_CODE: string = 'authorization_code';
    private readonly CLIENT_ID: string = 'client_id';
    private readonly CLIENT_SECRET: string = 'client_secret';
    private readonly REDIRECT_URI: string = 'redirect_uri';
    private readonly ACCESS_TOKEN: string = 'access_token';
    private readonly ID_TOKEN: string = 'id_token';
    private readonly SCOPE: string = 'scope';
    private readonly STATE: string = 'session_state';
    private readonly CODE_VERIFIER: string = 'code_verifier';
    private readonly REFRESH_TOKEN: string = 'refresh_token';
    constructor(public localStorage: LocalStorageBackend = new LocalStorage()) { }

    public async Authorize(tryAuthAuthorizationOptions: TryAuthAuthorizationOptions): Promise<void> {
        if (tryAuthAuthorizationOptions.ResponseType === this.RESPONSE_TYPE_IDTOKEN_TOKEN || tryAuthAuthorizationOptions.ResponseType === this.RESPONSE_TYPE_TOKEN_IDTOKEN) {
            await this.AuthorizeIdTokenToken(tryAuthAuthorizationOptions);
        }
        // throw error
    }

    public GetRedirect(tryAuthAuthorizationOptions: TryAuthAuthorizationOptions) {
        if (tryAuthAuthorizationOptions.ResponseType === this.RESPONSE_TYPE_IDTOKEN_TOKEN || tryAuthAuthorizationOptions.ResponseType === this.RESPONSE_TYPE_TOKEN_IDTOKEN) {
            this.GetRedirectAuthorizeIdTokenToken(tryAuthAuthorizationOptions);
        }
        // throw error
    }

    public async GetAuthorizationCode(tryAuthAuthorizationOptions: TryAuthAuthorizationOptions): Promise<void> {
        if (tryAuthAuthorizationOptions.ResponseType === this.RESPONSE_TYPE_CODE) {
            await this.GetRedirectAuthorizeCode(tryAuthAuthorizationOptions);
        }
    }

    public async LogoutAuthorizationCode(tryAuthAuthorizationOptions: TryAuthAuthorizationOptions): Promise<void> {
        if (tryAuthAuthorizationOptions.ResponseType === this.RESPONSE_TYPE_CODE) {
            await this.GetLogoutAuthorizationCode(tryAuthAuthorizationOptions);
        }
    }

    public LogoutEndSessionAuthorizationCode(tryAuthAuthorizationOptions: TryAuthAuthorizationOptions): void {
        if (tryAuthAuthorizationOptions.ResponseType === this.RESPONSE_TYPE_CODE) {
            this.GetLogoutEndSessionAuthorizationCode(tryAuthAuthorizationOptions);
        }
    }

    public async CheckAuthorize(): Promise<TryAuthAuthorizationResponse> {
        const tryAuthAuthorizationResponse: TryAuthAuthorizationResponse = this.GetResponseData();
        const jwtPayload = this.GetJwtPayload(tryAuthAuthorizationResponse.IdToken);
        const isNonceValid = await this.ValidateNonce(jwtPayload.nonce);
        if (!isNonceValid) {
            const tryAuthError: TryAuthError = new TryAuthError();
            tryAuthError.error = 'invalid nonce';
            tryAuthAuthorizationResponse.Error = tryAuthError;
            return tryAuthAuthorizationResponse;
        }
        tryAuthAuthorizationResponse.ExpiresAt = jwtPayload.exp * 1000;
        tryAuthAuthorizationResponse.Email = jwtPayload.email;
        // validate expires at 'exp'
        // validate expired 'iat'
        // validate not before 'nbf'
        await this.localStorage.removeItem(this.NONCE_KEY);
        return tryAuthAuthorizationResponse;
    }

    public CheckRedirect(): TryAuthAuthorizationResponse {
        const tryAuthAuthorizationResponse: TryAuthAuthorizationResponse = this.GetResponseData();
        const jwtPayload = this.GetJwtPayload(tryAuthAuthorizationResponse.IdToken);
        tryAuthAuthorizationResponse.ExpiresAt = jwtPayload.exp * 1000;
        tryAuthAuthorizationResponse.Email = jwtPayload.email;
        // validate expires at 'exp'
        // validate expired 'iat'
        // validate not before 'nbf'
        this.localStorage.removeItemSync(this.NONCE_KEY);
        return tryAuthAuthorizationResponse;
    }

    public GetSilentAuthorizationCodeToken(tryAuthAuthorizationOptions: TryAuthAuthorizationOptions): TryAuthAuthorizationCodeTokenResponse {
        const tryAuthAuthorizationCodeResponse: TryAuthAuthorizationCodeResponse = this.GetAuthorizationCodeReponseData();
        const response: string = this.PostAuthorizationCodeToken(tryAuthAuthorizationOptions, tryAuthAuthorizationCodeResponse);
        const tryAuthSerialize = new TryAuthSerialize();
        const serialized = tryAuthSerialize.Deserialize(response);

        const tryAuthAuthorizationCodeTokenResponse = new TryAuthAuthorizationCodeTokenResponse();
        if (serialized.access_token != null && serialized.access_token != undefined) {
            tryAuthAuthorizationCodeTokenResponse.AccessToken = serialized.access_token;
            tryAuthAuthorizationCodeTokenResponse.IdToken = serialized.id_token;
            if (serialized.refresh_token != null && serialized.refresh_token != undefined)
                tryAuthAuthorizationCodeTokenResponse.RefreshToken = serialized.refresh_token;
            tryAuthAuthorizationCodeTokenResponse.ExpiresIn = serialized.expires_in;
            tryAuthAuthorizationCodeTokenResponse.TokenType = serialized.token_type;
        }
        else {
            tryAuthAuthorizationCodeTokenResponse.Error = new TryAuthError();
            tryAuthAuthorizationCodeTokenResponse.Error.error = serialized.error;
        }
        return tryAuthAuthorizationCodeTokenResponse;
    }

    public GetAuthorizationCodeRefreshToken(tryAuthAuthorizationOptions: TryAuthAuthorizationOptions): TryAuthAuthorizationCodeTokenResponse {
        const response: string = this.PostAuthorizationCodeRefreshToken(tryAuthAuthorizationOptions);
        const tryAuthSerialize = new TryAuthSerialize();
        const serialized = tryAuthSerialize.Deserialize(response);

        const tryAuthAuthorizationCodeTokenResponse = new TryAuthAuthorizationCodeTokenResponse();
        if (serialized.access_token != null && serialized.access_token != undefined) {
            tryAuthAuthorizationCodeTokenResponse.AccessToken = serialized.access_token;
            tryAuthAuthorizationCodeTokenResponse.IdToken = serialized.id_token;
            if (serialized.refresh_token != null && serialized.refresh_token != undefined)
                tryAuthAuthorizationCodeTokenResponse.RefreshToken = serialized.refresh_token;
            tryAuthAuthorizationCodeTokenResponse.ExpiresIn = serialized.expires_in;
            tryAuthAuthorizationCodeTokenResponse.TokenType = serialized.token_type;
        }
        else {
            tryAuthAuthorizationCodeTokenResponse.Error = new TryAuthError();
            tryAuthAuthorizationCodeTokenResponse.Error.error = serialized.error;
        }
        return tryAuthAuthorizationCodeTokenResponse;
    }

    private Redirect(): void {
        const urlToRedirect: string = this.GetResponseLocationUrlSync();
        if (urlToRedirect != null && urlToRedirect.length > 0) {
            window.location.href = urlToRedirect;
        }
    }

    private GetResponseData(): TryAuthAuthorizationResponse {
        const map = this.GetAuthorizationKeyValue();
        const access_token = map.get(this.ACCESS_TOKEN);
        const id_token = map.get(this.ID_TOKEN);
        const tryAuthAuthorizationResponse: TryAuthAuthorizationResponse = new TryAuthAuthorizationResponse();
        tryAuthAuthorizationResponse.AccessToken = access_token;
        tryAuthAuthorizationResponse.IdToken = id_token;
        return tryAuthAuthorizationResponse;
    }

    private GetAuthorizationCodeReponseData(): TryAuthAuthorizationCodeResponse {
        const map = this.GetAuthorizationCodeKeyValue();
        const code = map.get(this.RESPONSE_TYPE_CODE);
        const scope = map.get(decodeURIComponent(this.SCOPE));
        const state = map.get(this.STATE);
        const tryAuthAuthorizationCodeResponse: TryAuthAuthorizationCodeResponse = new TryAuthAuthorizationCodeResponse();
        tryAuthAuthorizationCodeResponse.Code = code;
        tryAuthAuthorizationCodeResponse.Scope = scope;
        tryAuthAuthorizationCodeResponse.State = state;
        return tryAuthAuthorizationCodeResponse;
    }

    private GetJwtPayload(idToken: string): JwtPayload {
        return JwtDecode<JwtPayload>(idToken);
    }

    private GetExpiresAt(expiresAtTick: number): Date {
        const tick = expiresAtTick * 1000;
        return new Date(tick);
    }

    private async ValidateNonce(nonce: string): Promise<boolean> {
        const nonceStored = await this.localStorage.getItem(this.NONCE_KEY);
        if (nonce === nonceStored) {
            return true;
        }
        return false;
    }

    private GetAuthorizationKeyValue(): Map<string, string> {
        let hash: string = window.location.hash; // this will receive the '#id_token=...'
        if (hash.startsWith('#')) {
            // throw error
        }
        hash = hash.substring(1); // remove the '#'
        const split: string[] = hash.split('&');
        const map = new Map<string, string>();
        for (let i = 0; i < split.length; i++) {
            const keys = split[i];
            const keyValue = keys.split('=');
            map.set(keyValue[0], keyValue[1]);
        }
        return map;
    }

    private GetAuthorizationCodeKeyValue(): Map<string, string> {
        let hash: string = window.location.search; // this will receive the '#code, scope and session_state ...'
        hash = hash.substring(1); // remove the '?'
        const map = new Map<string, string>();
        const split: string[] = hash.split('&');
        for (let i = 0; i < split.length; i++) {
            const keys = split[i];
            const keyValue = keys.split('=');
            map.set(keyValue[0], keyValue[1]);
        }
        return map;
    }

    private async AuthorizeIdTokenToken(tryAuthAuthorizationOptions: TryAuthAuthorizationOptions): Promise<void> {
        const headers = this.SetDefaultHeaders();
        const authorizeEndpoint = await this.GetAuthorizeEndpoint(tryAuthAuthorizationOptions);
        return new Promise<void>((resolve, reject) => {
            const xhr: XMLHttpRequest = new XMLHttpRequest();
            xhr.withCredentials = false; // add Authorize in header
            xhr.onload = async () => {
                window.location.href = xhr.responseURL; // redirect to response location header of authorize endpoint
            };
            xhr.open('GET', authorizeEndpoint, true); // call the authorize endpoint
            for (let i: number = 0; i < headers.length; i++) {
                const header: [string, string] = headers[i];
                xhr.setRequestHeader(header[0], this.EnsureASCII(header[1]));
            }
            xhr.send(null);
        });
    }

    private GetRedirectAuthorizeIdTokenToken(tryAuthAuthorizationOptions: TryAuthAuthorizationOptions): void {
        const headers = this.SetDefaultHeaders();
        const authorizeEndpoint = this.GetAuthorizeEndpointSync(tryAuthAuthorizationOptions);
        const xhr: XMLHttpRequest = new XMLHttpRequest();
        xhr.withCredentials = false; // add Authorize in header
        xhr.onload = () => {
            window.location.href = xhr.responseURL; // redirect to response location header of authorize endpoint
        };
        xhr.open('GET', authorizeEndpoint, true); // call the authorize endpoint
        for (let i: number = 0; i < headers.length; i++) {
            const header: [string, string] = headers[i];
            xhr.setRequestHeader(header[0], this.EnsureASCII(header[1]));
        }
        xhr.send(null);
    }

    private async GetRedirectAuthorizeCode(tryAuthAuthorizationOptions: TryAuthAuthorizationOptions): Promise<void> {
        const crypto = new Crypto();
        const tryAuthPkceCode = await crypto.GeneratePkceCodes();
        if (tryAuthAuthorizationOptions.RequirePkce)
            tryAuthAuthorizationOptions.CodeChallenge = tryAuthPkceCode.CodeChallenge;
        await this.SetCodeVerifier(tryAuthPkceCode.CodeVerifier);
        
        let authorizeEndpoint = this.GetAuthorizationCodeEndpoint(tryAuthAuthorizationOptions);
        await this.SendRequest(authorizeEndpoint)
    }

    private async GetLogoutAuthorizationCode(tryAuthAuthorizationOptions: TryAuthAuthorizationOptions): Promise<void> {
        const crypto = new Crypto();
        const tryAuthPkceCode = await crypto.GeneratePkceCodes();
        tryAuthAuthorizationOptions.CodeChallenge = tryAuthPkceCode.CodeChallenge;
        await this.SetCodeVerifier(tryAuthPkceCode.CodeVerifier);

        let authorizeEndpoint = this.GetLogoutEndpoint(tryAuthAuthorizationOptions);
        const xhr: XMLHttpRequest = new XMLHttpRequest();
        xhr.withCredentials = false; // add Authorize in header
        xhr.onload = () => {
            window.location.href = xhr.responseURL; // redirect to response location header of authorize endpoint
        };
        xhr.open('GET', authorizeEndpoint, true); // call the authorize endpoint
        const headers = this.SetDefaultHeaders();
        for (let i: number = 0; i < headers.length; i++) {
            const header: [string, string] = headers[i];
            xhr.setRequestHeader(header[0], this.EnsureASCII(header[1]));
        }
        xhr.send(null);
    }

    private GetLogoutEndSessionAuthorizationCode(tryAuthAuthorizationOptions: TryAuthAuthorizationOptions): void {
        let authorizeEndpoint = this.GetLogoutEndSessionEndpoint(tryAuthAuthorizationOptions);
        const xhr: XMLHttpRequest = new XMLHttpRequest();
        xhr.withCredentials = false; // add Authorize in header
        xhr.onload = () => {
            window.location.href = xhr.responseURL; // redirect to response location header of authorize endpoint
        };
        xhr.open('GET', authorizeEndpoint, true); // call the authorize endpoint
        const headers = this.SetDefaultHeaders();
        for (let i: number = 0; i < headers.length; i++) {
            const header: [string, string] = headers[i];
            xhr.setRequestHeader(header[0], this.EnsureASCII(header[1]));
        }
        xhr.send(null);
    }

    private PostAuthorizationCodeToken(tryAuthAuthorizationOptions: TryAuthAuthorizationOptions, tryAuthAuthorizationCodeResponse: TryAuthAuthorizationCodeResponse): string {
        const headers = this.SetDefaultHeaders();
        const codeVerifier = this.GetCodeVerifier();
        const parameters = new URLSearchParams();
        parameters.append(this.GRANT_TYPE, this.AUTHORIZATION_CODE);
        parameters.append(this.CLIENT_ID, tryAuthAuthorizationOptions.ClientId);
        parameters.append(this.CLIENT_SECRET, tryAuthAuthorizationOptions.ClientSecret);
        parameters.append(this.RESPONSE_TYPE_CODE, tryAuthAuthorizationCodeResponse.Code);
        parameters.append(this.CODE_VERIFIER, codeVerifier);
        
        if (tryAuthAuthorizationOptions.RedirectUri == null || tryAuthAuthorizationOptions.RedirectUri == undefined || tryAuthAuthorizationOptions.RedirectUri === '')
            parameters.append(this.REDIRECT_URI, window.location.origin);
        else
            parameters.append(this.REDIRECT_URI, tryAuthAuthorizationOptions.RedirectUri);
        const tokenEndpoint = this.GetConnectTokenEndpoint(tryAuthAuthorizationOptions.IssuerEndpoint);
        const xhr: XMLHttpRequest = new XMLHttpRequest();
        xhr.withCredentials = false; // add Authorize in header
        xhr.open('POST', tokenEndpoint, false); // call the token endpoint synchronous (false)
        for (let i: number = 0; i < headers.length; i++) {
            const header: [string, string] = headers[i];
            xhr.setRequestHeader(header[0], this.EnsureASCII(header[1]));
        }
        xhr.send(parameters);
        return xhr.responseText;
    }

    private PostAuthorizationCodeRefreshToken(tryAuthAuthorizationOptions: TryAuthAuthorizationOptions): string {
        const headers = this.SetDefaultHeaders();
        const parameters = new URLSearchParams();
        parameters.append(this.GRANT_TYPE, this.REFRESH_TOKEN);
        parameters.append(this.CLIENT_ID, tryAuthAuthorizationOptions.ClientId);
        parameters.append(this.CLIENT_SECRET, tryAuthAuthorizationOptions.ClientSecret);
        parameters.append(this.REFRESH_TOKEN, tryAuthAuthorizationOptions.RefreshToken);
        const tokenEndpoint = this.GetConnectTokenEndpoint(tryAuthAuthorizationOptions.IssuerEndpoint);
        const xhr: XMLHttpRequest = new XMLHttpRequest();
        xhr.withCredentials = false; // add Authorize in header
        xhr.open('POST', tokenEndpoint, false); // call the token endpoint synchronous (false)
        for (let i: number = 0; i < headers.length; i++) {
            const header: [string, string] = headers[i];
            xhr.setRequestHeader(header[0], this.EnsureASCII(header[1]));
        }
        xhr.send(parameters);
        return xhr.responseText;
    }

    private SetDefaultHeaders(): [string, string][] {
        const headers: [string, string][] = [];
        headers.push(['Content-Type', 'application/x-www-form-urlencoded']); // together withCredentials do not as for CORS
        return headers;
    }

    private async SetNonceLocalStorage(): Promise<string> {
        const crypto = new Crypto(30);
        const nonce: string = crypto.Create();
        await this.localStorage.setItem(this.NONCE_KEY, nonce);
        return nonce;
    }

    private SetNonceLocalStorageSync(): string {
        const crypto = new Crypto(30);
        const nonce: string = crypto.Create();
        this.localStorage.setItemSync(this.NONCE_KEY, nonce);
        return nonce;
    }

    private async SetResponseLocationUrl(responseUrl: string): Promise<void> {
        await this.localStorage.setItem(this.REPONSE_URL_KEY, responseUrl);
    }

    private SetCodeVerifier(code: string): void {
        this.localStorage.setItemSync(this.CODE_VERIFIER, code);
    }

    private GetCodeVerifier(): string {
        return this.localStorage.getItemSync(this.CODE_VERIFIER);
    }

    private async GetResponseLocationUrl(): Promise<string> {
        return await this.localStorage.getItem(this.REPONSE_URL_KEY);
    }

    private GetResponseLocationUrlSync(): string {
        return this.localStorage.getItemSync(this.REPONSE_URL_KEY);
    }

    private GetHeaderValue(headers: [string, string][], name: string): string {
        for (let i: number = 0; i < headers.length; i++) {
            const header: [string, string] = headers[i];
            if (header[0].toLowerCase() === name.toLowerCase())
                return (header[1]);
        }
        return null;
    }

    private GetConnectAuthorizeEndpoint(issuerEndpoint: string): string {
        return issuerEndpoint + '/connect/authorize';
    }

    private GetConnectTokenEndpoint(issuerEndpoint: string): string {
        return issuerEndpoint + '/connect/token';
    }

    private LogoutEndpoint(issuerEndpoint: string): string {
        return issuerEndpoint + '/Identity/Logout';
    }

    private EndSessionEndpoint(issuerEndpoint: string): string {
        return issuerEndpoint + '/connect/endsession';
    }

    private async GetAuthorizeEndpoint(tryAuthAuthorizationOptions: TryAuthAuthorizationOptions): Promise<string> {
        const nonce: string = await this.SetNonceLocalStorage();
        let authorizeEndpoint = this.GetConnectAuthorizeEndpoint(tryAuthAuthorizationOptions.IssuerEndpoint);
        authorizeEndpoint = authorizeEndpoint + '?client_id=' + tryAuthAuthorizationOptions.ClientId;
        if (tryAuthAuthorizationOptions.RedirectUri == null) {
            authorizeEndpoint = authorizeEndpoint + '&redirect_uri=' + encodeURIComponent(window.location.origin);
        }
        else {
            authorizeEndpoint = authorizeEndpoint + '&redirect_uri=' + encodeURIComponent(tryAuthAuthorizationOptions.RedirectUri);
        }
        const ensureExternalIssuerEndpoint = this.EnsureExternalIssuerEndpoint(tryAuthAuthorizationOptions.ExternalIssuerEndpoint);
        if (ensureExternalIssuerEndpoint != null) {
            authorizeEndpoint = authorizeEndpoint + '&external_uri=' + encodeURIComponent(ensureExternalIssuerEndpoint);
        }
        if (tryAuthAuthorizationOptions.ExternalClientId != null) {
            authorizeEndpoint = authorizeEndpoint + '&external_client_id=' + tryAuthAuthorizationOptions.ExternalClientId;
        }
        authorizeEndpoint = authorizeEndpoint + '&response_type=' + tryAuthAuthorizationOptions.ResponseType;
        authorizeEndpoint = authorizeEndpoint + '&scope=' + tryAuthAuthorizationOptions.Scopes;
        authorizeEndpoint = authorizeEndpoint + '&nonce=' + nonce;
        return authorizeEndpoint;
    }

    private GetAuthorizeEndpointSync(tryAuthAuthorizationOptions: TryAuthAuthorizationOptions): string {
        const nonce: string = this.SetNonceLocalStorageSync();
        let authorizeEndpoint = this.GetConnectAuthorizeEndpoint(tryAuthAuthorizationOptions.IssuerEndpoint);
        authorizeEndpoint = authorizeEndpoint + '?client_id=' + tryAuthAuthorizationOptions.ClientId;
        if (tryAuthAuthorizationOptions.RedirectUri == null) {
            authorizeEndpoint = authorizeEndpoint + '&redirect_uri=' + encodeURIComponent(window.location.origin);
        }
        else {
            authorizeEndpoint = authorizeEndpoint + '&redirect_uri=' + encodeURIComponent(tryAuthAuthorizationOptions.RedirectUri);
        }
        const ensureExternalIssuerEndpoint = this.EnsureExternalIssuerEndpoint(tryAuthAuthorizationOptions.ExternalIssuerEndpoint);
        if (ensureExternalIssuerEndpoint != null) {
            authorizeEndpoint = authorizeEndpoint + '&external_uri=' + encodeURIComponent(ensureExternalIssuerEndpoint);
        }
        if (tryAuthAuthorizationOptions.ExternalClientId != null) {
            authorizeEndpoint = authorizeEndpoint + '&external_client_id=' + tryAuthAuthorizationOptions.ExternalClientId;
        }
        authorizeEndpoint = authorizeEndpoint + '&response_type=' + tryAuthAuthorizationOptions.ResponseType;
        authorizeEndpoint = authorizeEndpoint + '&scope=' + tryAuthAuthorizationOptions.Scopes;
        authorizeEndpoint = authorizeEndpoint + '&nonce=' + nonce;
        return authorizeEndpoint;
    }

    private GetAuthorizationCodeEndpoint(tryAuthAuthorizationOptions: TryAuthAuthorizationOptions): string {
        let authorizeEndpoint = this.GetConnectAuthorizeEndpoint(tryAuthAuthorizationOptions.IssuerEndpoint);
        authorizeEndpoint = authorizeEndpoint + '?client_id=' + tryAuthAuthorizationOptions.ClientId;
        if (tryAuthAuthorizationOptions.RedirectUri == null) {
            authorizeEndpoint = authorizeEndpoint + '&redirect_uri=' + encodeURIComponent(window.location.origin);
        }
        else {
            authorizeEndpoint = authorizeEndpoint + '&redirect_uri=' + encodeURIComponent(tryAuthAuthorizationOptions.RedirectUri);
        }
        authorizeEndpoint = authorizeEndpoint + '&response_type=' + tryAuthAuthorizationOptions.ResponseType;
        authorizeEndpoint = authorizeEndpoint + '&scope=' + tryAuthAuthorizationOptions.Scopes;
        if (tryAuthAuthorizationOptions.CodeChallenge != null) {
            authorizeEndpoint = authorizeEndpoint + '&code_challenge=' + tryAuthAuthorizationOptions.CodeChallenge;
            authorizeEndpoint = authorizeEndpoint + '&code_challenge_method=S256';
        }
        return authorizeEndpoint;
    }

    private GetLogoutEndpoint(tryAuthAuthorizationOptions: TryAuthAuthorizationOptions): string {
        let authorizeEndpoint = this.LogoutEndpoint(tryAuthAuthorizationOptions.IssuerEndpoint);
        authorizeEndpoint = authorizeEndpoint + '?returnUrl=' + encodeURIComponent('/connect/authorize');
        authorizeEndpoint = authorizeEndpoint + '&client_id=' + tryAuthAuthorizationOptions.ClientId;
        if (tryAuthAuthorizationOptions.RedirectUri == null) {
            authorizeEndpoint = authorizeEndpoint + '&redirect_uri=' + encodeURIComponent(window.location.origin);
        }
        else {
            authorizeEndpoint = authorizeEndpoint + '&redirect_uri=' + encodeURIComponent(tryAuthAuthorizationOptions.RedirectUri);
        }
        authorizeEndpoint = authorizeEndpoint + '&response_type=' + tryAuthAuthorizationOptions.ResponseType;
        authorizeEndpoint = authorizeEndpoint + '&scope=' + tryAuthAuthorizationOptions.Scopes;
        if (tryAuthAuthorizationOptions.CodeChallenge != null) {
            authorizeEndpoint = authorizeEndpoint + '&code_challenge=' + tryAuthAuthorizationOptions.CodeChallenge;
            authorizeEndpoint = authorizeEndpoint + '&code_challenge_method=S256';
        }
        return authorizeEndpoint;
    }

    private GetLogoutEndSessionEndpoint(tryAuthAuthorizationOptions: TryAuthAuthorizationOptions): string {
        let authorizeEndpoint = this.EndSessionEndpoint(tryAuthAuthorizationOptions.IssuerEndpoint);
        authorizeEndpoint = authorizeEndpoint + '?id_token_hint=' + tryAuthAuthorizationOptions.IdToken;
        authorizeEndpoint = authorizeEndpoint + '&state=' + tryAuthAuthorizationOptions.State;
        authorizeEndpoint = authorizeEndpoint + '&post_logout_redirect_uri=' + tryAuthAuthorizationOptions.RedirectUri;
        return authorizeEndpoint;
    }

    private SendRequest(url: string): Promise<void> {
        return new Promise((resolve, reject) => {
            const xhr: XMLHttpRequest = new XMLHttpRequest();
            xhr.withCredentials = false;
    
            xhr.onload = () => {
                if (xhr.status >= 200 && xhr.status < 300) {
                    window.location.href = xhr.responseURL; // Redireciona para o endpoint autorizado
                    resolve();
                } else {
                    reject(new Error(`Error on request: ${xhr.status} - ${xhr.statusText}`));
                }
            };
    
            xhr.onerror = () => reject(new Error("An error occurred while trying to process your request."));
            xhr.ontimeout = () => reject(new Error("The request timed out. Please try again later."));
    
            xhr.open("GET", url, true);
    
            const headers = this.SetDefaultHeaders();
            for (let i = 0; i < headers.length; i++) {
                const header: [string, string] = headers[i];
                xhr.setRequestHeader(header[0], this.EnsureASCII(header[1]));
            }
    
            xhr.send(null);
        });
    }

    private EnsureExternalIssuerEndpoint(externalIssuerEndpoint?: string): string {
        if (externalIssuerEndpoint == null)
            return '';

        if (externalIssuerEndpoint.endsWith('/'))
            externalIssuerEndpoint = externalIssuerEndpoint + 'authorize';
        else
            externalIssuerEndpoint = externalIssuerEndpoint + '/authorize';
        return externalIssuerEndpoint;
    }

    private EnsureASCII(data: string): string {
        if (this.HasUnicode(data))
            return (this.ConvertToASCII(data));
        return (data);
    }

    private HasUnicode(data: string): boolean {
        for (let i = 0; i < data.length; i++) {
            const char: string = data[i];
            const index: number = char.charCodeAt(0);
            if (index > 127)
                return (true);
        }
        return (false);
    }

    private ConvertToASCII(data: string): string {
        let encoded: string = '';
        for (let i = 0; i < data.length; i++) {
            const char: string = data[i];
            const index: number = char.charCodeAt(0);
            encoded += '\\u' + index.toString(16).toUpperCase();
        }
        return (encoded);
    }
}

class Crypto {
    private _size: number = null;
    private _charset: string = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    /**
     * The maximum length for a code verifier for the best security we can offer.
     * Please note the NOTE section of RFC 7636 § 4.1 - the length must be >= 43,
     * but <= 128, **after** base64 url encoding. This means 32 code verifier bytes
     * encoded will be 43 bytes, or 96 bytes encoded will be 128 bytes. So 96 bytes
     * is the highest valid value that can be used.
     */
    private _code_verifier_length: number = 96;
    /**
     * Character set to generate code verifier defined in rfc7636.
     */
    private _pkce_charset: string = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';

    /**
     * Implements *base64url-encode* (RFC 4648 § 5) without padding, which is NOT
     * the same as regular base64 encoding.
     */
    private base64urlEncode = (value: string): string => {
        let base64 = btoa(value);
        base64 = base64.replace(/\+/g, '-');
        base64 = base64.replace(/\//g, '_');
        base64 = base64.replace(/=/g, '');
        return base64;
    };

    constructor(size?: number) {
        this._size = size;
    }
    public Create(): string {
        const buffer = new Uint8Array(this._size);
        for (let i = 0; i < this._size; i += 1) {
            buffer[i] = (Math.random() * this._charset.length) | 0;
        }
        return this.BufferToString(buffer);
    }

    public Buffer: ArrayBuffer = null;
    public async GeneratePkceCodes(): Promise<TryAuthPkceCode> {
        const uint = new Uint32Array(this._code_verifier_length);
        crypto.getRandomValues(uint);
        const codeVerifier = this.base64urlEncode(Array.from(uint).map((num: number) => this._pkce_charset[num % this._pkce_charset.length]).join(''));
        const buffer = await crypto.subtle.digest('SHA-256', (new TextEncoder()).encode(codeVerifier));
        const hash = new Uint8Array(buffer);
        let binary = '';
        const hashLength = hash.byteLength;
        for (let i: number = 0; i < hashLength; i++) {
            binary += String.fromCharCode(hash[i]);
        }
        const codeChallenge = this.base64urlEncode(binary);
        const tryAuthPkceCode = new TryAuthPkceCode();
        tryAuthPkceCode.CodeVerifier = codeVerifier;
        tryAuthPkceCode.CodeChallenge = codeChallenge;
        
        return tryAuthPkceCode;
    }

    private BufferToString(buffer: Uint8Array): string {
        const state = [];
        for (let i = 0; i < buffer.byteLength; i += 1) {
            const index = buffer[i] % this._charset.length;
            state.push(this._charset[index]);
        }
        return state.join('');
    }
}

interface ILocalStorage {
    readonly length: number;
    clear(): void;
    getItem(key: string): string | null;
    removeItem(key: string): void;
    setItem(key: string, data: string): void;
}

abstract class LocalStorageBackend {
    //When passed a key `name`, will return that key's value.
    public abstract getItem(name: string): Promise<string | null>;
    public abstract getItemSync(name: string): string | null;
    //When passed a key `name`, will remove that key from the storage.
    public abstract removeItem(name: string): Promise<void>;
    public abstract removeItemSync(name: string): void;
    //When invoked, will empty all keys out of the storage.
    public abstract clear(): Promise<void>;
    //The setItem() method of the `ILocalStorage` interface,
    //when passed a key name and value, will add that key to the storage,
    //or update that key's value if it already exists.
    public abstract setItem(name: string, value: string): Promise<void>;
    public abstract setItemSync(name: string, value: string): void;
}

class LocalStorage extends LocalStorageBackend {
    private _storage: ILocalStorage;
    constructor(storage?: ILocalStorage) {
        super();
        this._storage = storage || window.localStorage;
    }
    public getItem(name: string): Promise<string | null> {
        return new Promise<string | null>((resolve, reject) => {
            const value = this._storage.getItem(name);
            if (value) {
                resolve(value);
            } else {
                resolve(null);
            }
        });
    }
    public getItemSync(name: string): string | null {
        const value = this._storage.getItem(name);
        if (value) {
            return value;
        } else {
            return null;
        }
    }
    public removeItem(name: string): Promise<void> {
        return new Promise<void>((resolve, reject) => {
            this._storage.removeItem(name);
            resolve();
        });
    }
    public removeItemSync(name: string): void {
        this._storage.removeItem(name);
    }
    public clear(): Promise<void> {
        return new Promise<void>((resolve, reject) => {
            this._storage.clear();
            resolve();
        });
    }
    public setItem(name: string, value: string): Promise<void> {
        return new Promise<void>((resolve, reject) => {
            this._storage.setItem(name, value);
            resolve();
        });
    }
    public setItemSync(name: string, value: string): void {
        this._storage.setItem(name, value);
    }
}

class TryAuthSerialize {
    private readonly JSON_START = '{';
    private readonly JSON_END = '}';
    private readonly JSON_ARRAY_START = '[';
    private readonly JSON_ARRAY_END = ']';

    private IsJson(data: string): boolean {
        return ((this.IsJsonInstance(data)) || (this.IsJsonArray(data)));
    }

    private IsJsonInstance(data: string): boolean {
        if (data === null)
            return (false);
        if (data.length < 2)
            return (false);
        return ((data.substr != null) && (data.substr(0, 1) == this.JSON_START) && (data.substr(data.length - 1, 1) == this.JSON_END));
    }

    private IsJsonArray(data: string): boolean {
        if (data === null)
            return (false);
        if (data.length < 2)
            return (false);
        return ((data.substr != null) && (data.substr(0, 1) == this.JSON_ARRAY_START) && (data.substr(data.length - 1, 1) == this.JSON_ARRAY_END));
    }

    public Deserialize(data: string): any {
        if (!this.IsJson(data))
            return (data);
        return (JSON.parse(data));
    }
}