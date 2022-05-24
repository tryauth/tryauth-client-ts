class TryAuthAuthorizationOptions {
    private _clientId: string = null;
    private _issuerEndpoint: string = null;
    private _responseType: string = null;
    private _scopes: string = null;

    get ClientId(): string {
        return this._clientId;
    }
    set ClientId(value: string) {
        this._clientId = value;
    }
    get IssuerEndpoint(): string {
        return this._issuerEndpoint;
    }
    set IssuerEndpoint(value: string) {
        this._issuerEndpoint = value;
    }
    get ResponseType(): string {
        return this._responseType;
    }
    set ResponseType(value: string) {
        this._responseType = value;
    }
    get Scopes(): string {
        return this._scopes;
    }
    set Scopes(value: string) {
        this._scopes = value;
    }
}