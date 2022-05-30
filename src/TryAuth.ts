import JwtDecode from 'jwt-decode';

export class TryAuthAuthorizationResponse {
    public AccessToken: string = null;
    public IdToken: string = null;
    public Error: TryAuthError = null;
}

class TryAuthAuthorizationOptions {
    public ClientId: string = null;
    public IssuerEndpoint: string = null;
    public ResponseType: string = null;
    public Scopes: string = null;
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
}

export default class TryAuth {
    private readonly NONCE_KEY = 'tryauth_authorization_nonce_key';
    private readonly RESPONSE_TYPE_IDTOKEN_TOKEN: string = 'id_token token';
    private readonly RESPONSE_TYPE_TOKEN_IDTOKEN: string = 'token id_token';
    private readonly RESPONSE_TYPE_CODE: string = 'code';
    private readonly ACCESS_TOKEN: string = 'access_token';
    private readonly ID_TOKEN: string = 'id_token';
    constructor(public localStorage: LocalStorageBackend = new LocalStorage()) { }

    public async Authorize(tryAuthAuthorizationOptions: TryAuthAuthorizationOptions): Promise<void> {
        if (tryAuthAuthorizationOptions.ResponseType === this.RESPONSE_TYPE_IDTOKEN_TOKEN || tryAuthAuthorizationOptions.ResponseType === this.RESPONSE_TYPE_TOKEN_IDTOKEN) {
            await this.AuthorizeIdTokenToken(tryAuthAuthorizationOptions);
        }
        // throw error
    }

    public async CheckAuthorize(): Promise<TryAuthAuthorizationResponse> {
        const tryAuthAuthorizationResponse: TryAuthAuthorizationResponse = this.GetResponseData();
        const nonceValid = await this.ValidateIdTokenNonce(tryAuthAuthorizationResponse.IdToken);
        if (!nonceValid) {
            const tryAuthError: TryAuthError = new TryAuthError();
            tryAuthError.error = 'invalid nonce';
            tryAuthAuthorizationResponse.Error = tryAuthError;
            return tryAuthAuthorizationResponse;
        }
        // validate expired iat
        // validate not before nbf
        await this.localStorage.removeItem(this.NONCE_KEY);
        return tryAuthAuthorizationResponse;
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

    private async ValidateIdTokenNonce(idToken: string): Promise<boolean> {
        const jwtPayload = JwtDecode<JwtPayload>(idToken);
        const nonceStored = await this.localStorage.getItem(this.NONCE_KEY);
        if (jwtPayload.nonce === nonceStored) {
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

    private async AuthorizeIdTokenToken(tryAuthAuthorizationOptions: TryAuthAuthorizationOptions): Promise<void> {
        const headers = this.SetDefaultHeaders();
        const authorizeEndpoint = await this.GetAuthorizeEndpoint(tryAuthAuthorizationOptions);
        return new Promise<void>((resolve, reject) => {
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
            //xhr.send(JSON.stringify(request));
            xhr.send(null);
        });
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

    private async GetAuthorizeEndpoint(tryAuthAuthorizationOptions: TryAuthAuthorizationOptions): Promise<string> {
        const nonce: string = await this.SetNonceLocalStorage();
        let authorizeEndpoint = this.GetConnectAuthorizeEndpoint(tryAuthAuthorizationOptions.IssuerEndpoint);
        authorizeEndpoint = authorizeEndpoint + '?client_id=' + tryAuthAuthorizationOptions.ClientId;
        authorizeEndpoint = authorizeEndpoint + '&redirect_uri=' + encodeURIComponent(window.location.origin);
        authorizeEndpoint = authorizeEndpoint + '&response_type=' + tryAuthAuthorizationOptions.ResponseType;
        authorizeEndpoint = authorizeEndpoint + '&scope=' + tryAuthAuthorizationOptions.Scopes;
        authorizeEndpoint = authorizeEndpoint + '&nonce=' + nonce;
        return authorizeEndpoint;
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
    constructor(size: number) {
        this._size = size;
    }
    public Create(): string {
        const buffer = new Uint8Array(this._size);
        for (let i = 0; i < this._size; i += 1) {
            buffer[i] = (Math.random() * this._charset.length) | 0;
        }
        return this.BufferToString(buffer);
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
    //When passed a key `name`, will remove that key from the storage.
    public abstract removeItem(name: string): Promise<void>;
    //When invoked, will empty all keys out of the storage.
    public abstract clear(): Promise<void>;
    //The setItem() method of the `ILocalStorage` interface,
    //when passed a key name and value, will add that key to the storage,
    //or update that key's value if it already exists.
    public abstract setItem(name: string, value: string): Promise<void>;
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
    public removeItem(name: string): Promise<void> {
        return new Promise<void>((resolve, reject) => {
            this._storage.removeItem(name);
            resolve();
        });
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
}