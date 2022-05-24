class TryAuth {
    constructor() {

    }

    public async Authorize(tryAuthAuthorizationOptions: TryAuthAuthorizationOptions): Promise<void> {
        const headers = this.SetDefaultHeaders();
        let authorizeEndpoint = this.GetAuthorizeEndpoint(tryAuthAuthorizationOptions.IssuerEndpoint);
        authorizeEndpoint = authorizeEndpoint + '?client_id=' + tryAuthAuthorizationOptions.ClientId;
        authorizeEndpoint = authorizeEndpoint + '&redirect_uri=' + encodeURIComponent(window.location.origin);
        authorizeEndpoint = authorizeEndpoint + '&response_type=' + tryAuthAuthorizationOptions.ResponseType;
        authorizeEndpoint = authorizeEndpoint + '&scope=' + tryAuthAuthorizationOptions.Scopes;
        authorizeEndpoint = authorizeEndpoint + '&nonce=3f6d2b3421cddf48e6b70ed7f2bb4a4be7EWZ7qSK';
        return new Promise(
            (resolve, reject) => {
                const xhr: XMLHttpRequest = new XMLHttpRequest();
                xhr.withCredentials = false; // add Authorize in header
                xhr.onload = () => {
                    window.location.href = xhr.responseURL;
                };
                xhr.open('GET', authorizeEndpoint, true);
                for (let i: number = 0; i < headers.length; i++) {
                    const header: [string, string] = headers[i];
                    xhr.setRequestHeader(header[0], this.EnsureASCII(header[1]));
                }
                //xhr.send(JSON.stringify(request));
                xhr.send(null);
            }
        );
    }

    private SetDefaultHeaders(): [string, string][] {
        let headers: [string, string][] = [];
        headers.push(['Content-Type', 'application/x-www-form-urlencoded']); // together withCredentials do not as for CORS
        return headers;
    }

    private GetHeaderValue(headers: [string, string][], name: string): string {
        for (let i: number = 0; i < headers.length; i++) {
            const header: [string, string] = headers[i];
            if (header[0].toLowerCase() === name.toLowerCase())
                return (header[1]);
        }
        return null;
    }

    private GetTokenEndpoint(issuerEndpoint: string): string {
        return issuerEndpoint + '/connect/token';
    }

    private GetAuthorizeEndpoint(issuerEndpoint: string): string {
        return issuerEndpoint + '/connect/authorize';
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