const request = require('./request');
const qs = require('querystring');

const apiVersion = 'v1';
const httpHeaders = {
    'Content-Type': 'application/json',
    'Cache-Control': 'no-cache',
    Pragma: 'no-cache',
};

class AuthorizationSeverSDK {

    constructor(options) {
        const {
            url,
            clientId,
            clientSecret,
            audience,
        } = options;

        this.url = url;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.audience = audience;
    }

    static request(...args) {
        return request(...args);
    }

    static encodeBasicToken({ username, password }) {
        return Buffer.from(`${username}:${password}`).toString('base64');
    }

    static decodeBasicToken(basicToken) {
        const credentials = Buffer.from(basicToken, 'base64').toString('ascii').split(':');

        return {
            username: credentials[0],
            password: credentials[1],
        };
    }

    static validateBearerToken(accessToken) {
        return /^Bearer [A-Za-z0-9\-\._~\+\/]+=*/.test(accessToken);
    }

    getToken(options) {
        const {
            username,
            password,
            scope,
        } = options;
        const {
            clientId,
            clientSecret,
        } = this;

        return request({
            method: 'POST',
            url: `${this.url}/${apiVersion}/oauth/token`,
            headers: httpHeaders,
            json: {
                grant_type: 'password',
                username,
                password,
                scope,
                client_id: clientId,
                client_secret: clientSecret,
            },
        }).then(data => {
            return {
                accessToken: data.access_token,
                tokenType: data.token_type,
                expiresIn: data.expires_in,
                refreshToken: data.refresh_token,
            };
        });
    }

    authenticate(options) {
        const {
            accessToken,
            scope,
        } = options;
        const {
            clientId,
            clientSecret,
        } = this;

        return request({
            method: 'POST',
            url: `${this.url}/${apiVersion}/oauth/access_token`,
            headers: httpHeaders,
            json: {
                grant_type: 'access_token',
                access_token: accessToken,
                scope,
                client_id: clientId,
                client_secret: clientSecret,
            },
        }).then(data => {
            return {
                accessToken: data.access_token,
                tokenType: data.token_type,
                expiresIn: data.expires_in,
                refreshToken: data.refresh_token,
            };
        });
    }

    refreshToken({ refreshToken }) {
        const { clientId, clientSecret } = this;

        return request({
            method: 'POST',
            url: `${this.url}/${apiVersion}/oauth/refresh`,
            headers: httpHeaders,
            json: {
                grant_type: 'refresh_token',
                client_id: clientId,
                client_secret: clientSecret,
                refresh_token: refreshToken,
            },
        }).then(data => {
            return {
                accessToken: data.access_token,
                tokenType: data.token_type,
                expiresIn: data.expires_in,
                // tip: authorization server must revoke refresh token
                // and generate new access token and refresh token
                // based on same audience and scope.
                refreshToken: data.refresh_token,
            };
        });
    }

    _revokeRefreshToken({ refreshToken }) {
        const { clientId, clientSecret } = this;

        return request({
            method: 'POST',
            url: `${this.url}/${apiVersion}/oauth/revoke`,
            headers: httpHeaders,
            json: {
                client_id: clientId,
                client_secret: clientSecret,
                token: refreshToken,
            },
        }).then(() => {
            return {};
        });
    }

    authorize(options) {
        const {
            responseType = 'token',
            connection,
        } = options;
        const { clientId } = this;

        return request({
            method: 'POST',
            url: `${this.url}/${apiVersion}/authorize`,
            headers: httpHeaders,
            json: {
                response_type: responseType,
                client_id: clientId,
                connection,
            },
        }).then(data => {
            return {
                url: data.url,
            };
        });
    }

    signUp({ email, password, userMetadata = {} }) {
        const { clientId } = this;

        return request({
            method: 'POST',
            url: `${this.url}/${apiVersion}/sign_up`,
            headers: httpHeaders,
            json: {
                email,
                password,
                client_id: clientId,
                user_metadata: userMetadata,
            },
        }).then(data => {
            return {
                uid: data.uid,
            };
        });
    }

    changePassword({ email, password }) {
        const { clientId } = this;

        return request({
            method: 'POST',
            url: `${this.url}/${apiVersion}/change_password`,
            headers: httpHeaders,
            json: {
                email,
                password,
                client_id: clientId,
            },
        }).then(() => {
            return {};
        });
    }

    getUserInfo({ accessToken }) {
        return request({
            method: 'GET',
            url: `${this.url}/${apiVersion}/user_info?access_token=${accessToken}`,
            headers: httpHeaders,
            json: {},
        });
    }

}

module.exports = AuthorizationSeverSDK;
