const expect = require('chai').expect;
const nock = require('nock');
const qs = require('querystring');

const AuthServerSDK = require('../src');

const testUrl = 'http://localhost:5000';
const clientId = 'ggg';
const clientSecret = 'kkk';
const audience = 'http://gghf.net';

const apiVersion = 'v1';

const sdk = new AuthServerSDK({
    url: testUrl,
    clientId,
    clientSecret,
    audience,
});

describe('sdk', () => {
    it('should validate bearer token properly', function * () {
        const result = AuthServerSDK.validateBearerToken('Bearer FSDdsfm3_f32');

        // eslint-disable-next-line no-unused-expression
        expect(result).to.be.ok;
    });

    it('should fails bearer token', function * () {
        const result = AuthServerSDK.validateBearerToken('FSDdsfm3_f32');

        // eslint-disable-next-line no-unused-expression
        expect(result).not.to.be.ok;
    });

    describe('should encode and decode basic token properly', () => {
        const auth = {
            username: 'GGG',
            password: 'K6rex_33',
        };
        let basicToken = null;

        it('should encode fine', function * () {
            const result = AuthServerSDK.encodeBasicToken(auth);

            // eslint-disable-next-line no-unused-expression
            expect(result).to.be.a('String');

            basicToken = result;
        });

        it('should decode fine', function * () {
            const result = AuthServerSDK.decodeBasicToken(basicToken);

            // eslint-disable-next-line no-unused-expression
            expect(result).to.eql(auth);
        });
    });

    it('should get token', function * () {
        const tokenInfo = {
            access_token: 'dfdsf',
            token_type: 'Bearer',
            expires_in: 86400,
            refresh_token: 'fmwef349dsf',
        };
        const user = {
            username: 'john.doe',
            password: '123456',
        };

        nock(testUrl)
            .post(`/${apiVersion}/oauth/token`, {
                grant_type: 'password',
                username: user.username,
                password: user.password,
                audience,
                scope: '',
                client_id: clientId,
                client_secret: clientSecret,
            })
            .reply(200, tokenInfo);

        const resp = yield sdk.getToken(user);

        expect(resp).to.eql({
            accessToken: tokenInfo.access_token,
            tokenType: tokenInfo.token_type,
            expiresIn: tokenInfo.expires_in,
            refreshToken: tokenInfo.refresh_token,
        });
    });

    it('should refresh token', function * () {
        const tokenInfo = {
            access_token: 'dfdsf',
            token_type: 'Bearer',
            expires_in: 86400,
            refresh_token: 'fmwef349dsf',
        };
        const refreshToken = 'adfasfds';

        nock(testUrl)
            .post(`/${apiVersion}/oauth/refresh`, {
                grant_type: 'refresh_token',
                client_id: clientId,
                client_secret: clientSecret,
                refresh_token: refreshToken,
            })
            .reply(200, tokenInfo);

        const resp = yield sdk.refreshToken({ refreshToken });

        expect(resp).to.eql({
            accessToken: tokenInfo.access_token,
            tokenType: tokenInfo.token_type,
            expiresIn: tokenInfo.expires_in,
            refreshToken: tokenInfo.refresh_token,
        });
    });

    it('should revoke refresh token [private]', function * () {
        const refreshToken = 'adfasfds';

        nock(testUrl)
            .post(`/${apiVersion}/oauth/revoke`, {
                client_id: clientId,
                client_secret: clientSecret,
                token: refreshToken,
            })
            .reply(200, {});

        const resp = yield sdk._revokeRefreshToken({ refreshToken });

        expect(resp).to.eql({});
    });

    it('should authorize with third', function * () {
        const connection = 'https://fb.api.com/v2.3';
        const connectUrl = 'https://fb.api.com/v2.3?someq=jj';

        nock(testUrl)
            .post(`/${apiVersion}/authorize`, {
                response_type: 'token',
                client_id: clientId,
                connection,
            })
            .reply(200, {
                url: connectUrl,
            });

        const resp = yield sdk.authorize({
            response_type: '',
            connection: 'https://fb.api.com/v2.3',
        });

        expect(resp).to.eql({
            url: connectUrl,
        });
    });

    it('should sign up', function * () {
        const user = {
            uid: 'fkwf43DAzf',
            email: 'john.doe@gmail.com',
            password: '123456',
        };

        nock(testUrl)
            .post(`/${apiVersion}/sign_up`, {
                email: user.email,
                password: user.password,
                client_id: clientId,
                user_metadata: {},
            })
            .reply(200, { uid: user.uid });

        const resp = yield sdk.signUp(user);

        expect(resp).to.eql({ uid: user.uid });
    });

    it('should change password', function * () {
        const user = {
            email: 'john.doe@gmail.com',
            password: '123456',
        };

        nock(testUrl)
            .post(`/${apiVersion}/change_password`, {
                email: user.email,
                password: user.password,
                client_id: clientId,
            })
            .reply(200, {});

        const resp = yield sdk.changePassword(user);

        expect(resp).to.eql({});
    });

    it('should get info', function * () {
        const user = {
            username: 'john.doe',
            password: '123456',
        };
        const accessToken = 'gkgfdsf324';

        nock(testUrl)
            .get(`/${apiVersion}/user_info?access_token=${accessToken}`)
            .reply(200, {
                username: user.username,
            });

        const resp = yield sdk.getUserInfo({ accessToken });

        expect(resp).to.eql({
            username: user.username,
        });
    });
});
