const chai = require('chai');
const chaiPassportStrategy = require('chai-passport-strategy');
const sinon = require('sinon');

const DiscordTokenStrategy = require('..');

const {assert} = chai;
chai.use(chaiPassportStrategy);

const CLIENT_CONFIG = {clientID: 'foo', clientSecret: 'bar'};
const FAKE_PROFILE = JSON.stringify({
	id: '268473310986240001',
	username: 'Discord',
	avatar: 'f749bb0cbeeb26ef21eca719337d20f1',
	discriminator: '0001',
	public_flags: 131072,
});

describe('DiscordTokenStrategy', function discordTokenStrategyTests() {
	describe('DiscordTokenStrategy:constructor', function constructorTests() {
		it('Should export Strategy constructor', function exportTest() {
			assert.isFunction(DiscordTokenStrategy);
		});

		it('Should properly initialize', function initializeTest() {
			const strategy = new DiscordTokenStrategy(CLIENT_CONFIG, () => {});
			assert.equal(strategy.name, 'discord-token');
			assert.equal(strategy._oauth2._useAuthorizationHeaderForGET, true);
		});

		it('Should raise an exception when `options` is not provided', function optionsTest() {
			assert.throw(() => new DiscordTokenStrategy(), Error);
		});
	});

	describe('DiscordTokenStrategy:authenticate', function authenticateTests() {
		describe('Authenticate without `passReqToCallback`', function authNoPassReqToCallbackTest() {
			let strategy;

			before(function strategySetup() {
				strategy = new DiscordTokenStrategy(CLIENT_CONFIG, (accessToken, refreshToken, profile, next) => {
					assert.equal(accessToken, 'access_token');
					assert.equal(refreshToken, 'refresh_token');
					assert.typeOf(profile, 'object');
					assert.typeOf(next, 'function');
					return next(null, profile, {info: 'foo'});
				});

				sinon
					.stub(strategy._oauth2, 'get')
					.callsFake((_url, _accessToken, next) => next(null, FAKE_PROFILE, null));
			});

			after(function strategyCleanup() { strategy._oauth2.get.restore(); });

			const ChaiPassportParseTest = (done, reqConfig) => chai.passport
				.use(strategy)
				.success((user, info) => {
					assert.typeOf(user, 'object');
					assert.typeOf(info, 'object');
					assert.deepEqual(info, {info: 'foo'});
					done();
				}).req(reqConfig).authenticate({});

			it('Should properly parse `access_token` from body', function bodyParseTest(done) {
				ChaiPassportParseTest(done, (req) => {
					req.body = {
						access_token: 'access_token',
						refresh_token: 'refresh_token',
					};
				});
			});

			it('Should properly parse `access_token` from query parameters', function queryParseTest(done) {
				ChaiPassportParseTest(done, (req) => {
					req.query = {
						access_token: 'access_token',
						refresh_token: 'refresh_token',
					};
				});
			});

			it('Should properly parse access token from OAuth2 bearer header', function headerTest1(done) {
				ChaiPassportParseTest(done, (req) => {
					req.headers = {
						Authorization: 'Bearer access_token',
						refresh_token: 'refresh_token',
					};
				});
			});

			it('Should properly parse access token from OAuth2 bearer header (lowercase)', function headerTest2(done) {
				ChaiPassportParseTest(done, (req) => {
					req.headers = {
						authorization: 'Bearer access_token',
						refresh_token: 'refresh_token',
					};
				});
			});

			it('Should call fail if neither access token nor refresh token is provided', function failTest(done) {
				chai.passport.use(strategy).fail((error) => {
					assert.typeOf(error, 'object');
					assert.typeOf(error.message, 'string');
					assert.valueOf(error.message,
						'Neither access token nor refresh token could be parsed from the request');
					done();
				}).authenticate({});
			});

			it('Should call error if only a refresh token is provided (with invalid client credentials)',
				function refreshTest(done) {
					chai.passport.use(strategy).error((error) => {
						assert.typeOf(error, 'object');
						assert.typeOf(error.statusCode, 'number');
						assert.typeOf(error.data, 'string');
						assert.valueOf(error.statusCode, 400);
						assert.valueOf(error.data, '{"client_id": ["Value \\"foo\\" is not snowflake."]}');
						done();
					}).req((req) => {
						req.body = {
							refresh_token: 'refresh_token',
						};
					}).authenticate({});
				});
		});

		describe('Authenticate with `passReqToCallback`', function authPassReqToCallbackTest() {
			it('Should call the strategy\'s `_verify` method with `req`', function verifyMethodTest(done) {
				const strategy = new DiscordTokenStrategy(
					{...CLIENT_CONFIG, passReqToCallback: true},
					(req, accessToken, refreshToken, profile, next) => {
						assert.typeOf(req, 'object');
						assert.equal(accessToken, 'access_token');
						assert.equal(refreshToken, 'refresh_token');
						assert.typeOf(profile, 'object');
						assert.typeOf(next, 'function');
						return next(null, profile, {info: 'foo'});
					},
				);

				sinon
					.stub(strategy._oauth2, 'get')
					.callsFake((_url, _accessToken, next) => next(null, FAKE_PROFILE, null));

				chai.passport
					.use(strategy)
					.success((user, info) => {
						assert.typeOf(user, 'object');
						assert.typeOf(info, 'object');
						assert.deepEqual(info, {info: 'foo'});
						done();
					}).req((req) => {
						req.body = {
							access_token: 'access_token',
							refresh_token: 'refresh_token',
						};
					}).authenticate({});

				strategy._oauth2.get.restore();
			});
		});
	});

	describe('DiscordTokenStrategy:userProfile', function userProfileTests() {
		// TODO
	});

	describe('Authentication Failure', function authFailureTests() {
		// TODO
	});
});
