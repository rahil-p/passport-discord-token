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

describe('DiscordTokenStrategy', function strategyTests() {
	describe('DiscordTokenStrategy:constructor', function constructorTests() {
		it('Should export Strategy constructor', function test() {
			assert.isFunction(DiscordTokenStrategy);
		});

		it('Should properly initialize', function test() {
			const strategy = new DiscordTokenStrategy(CLIENT_CONFIG, () => {});
			assert.equal(strategy.name, 'discord-token');
			assert.equal(strategy._oauth2._useAuthorizationHeaderForGET, true);
		});

		it('Should raise an exception when `options` is not provided', function test() {
			assert.throw(() => new DiscordTokenStrategy(), Error);
		});
	});

	describe('DiscordTokenStrategy:authenticate', function authenticateTests() {
		describe('Authenticate without `passReqToCallback`', function authenticateInnerTests() {
			let strategy;

			before(function strategySetup() {
				strategy = new DiscordTokenStrategy(CLIENT_CONFIG, (accessToken, refreshToken, profile, next) => {
					assert.equal(accessToken, 'access_token');
					assert.equal(refreshToken, 'refresh_token');
					assert.typeOf(profile, 'object');
					assert.typeOf(next, 'function');
					return next(null, profile, {info: 'info'});
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
					assert.deepEqual(info, {info: 'info'});
					done();
				}).req(reqConfig).authenticate({});

			it('Should properly parse access token from body', function test(done) {
				ChaiPassportParseTest(done, (req) => {
					req.body = {
						access_token: 'access_token',
						refresh_token: 'refresh_token',
					};
				});
			});

			it('Should properly parse access token from query parameters', function test(done) {
				ChaiPassportParseTest(done, (req) => {
					req.query = {
						access_token: 'access_token',
						refresh_token: 'refresh_token',
					};
				});
			});

			it('Should properly parse access token from query parameters (despite case mismatch)',
				function headerTest1(done) {
					ChaiPassportParseTest(done, (req) => {
						req.headers = {
							access_token: 'access_token',
							REFRESH_TOKEN: 'refresh_token',
						};
					});
				});

			it('Should properly parse access token from OAuth2 bearer header', function test(done) {
				ChaiPassportParseTest(done, (req) => {
					req.headers = {
						Authorization: 'Bearer access_token',
						refresh_token: 'refresh_token',
					};
				});
			});

			it('Should properly parse access token from OAuth2 bearer header (lowercase)', function test(done) {
				ChaiPassportParseTest(done, (req) => {
					req.headers = {
						authorization: 'Bearer access_token',
						refresh_token: 'refresh_token',
					};
				});
			});
		});

		describe('Authenticate with `passReqToCallback`', function authenticateInnerTests() {
			it('Should call the strategy\'s `_verify` method with `req`', function test(done) {
				const strategy = new DiscordTokenStrategy(
					{...CLIENT_CONFIG, passReqToCallback: true},
					(req, accessToken, refreshToken, profile, next) => {
						assert.typeOf(req, 'object');
						assert.equal(accessToken, 'access_token');
						assert.equal(refreshToken, 'refresh_token');
						assert.typeOf(profile, 'object');
						assert.typeOf(next, 'function');
						return next(null, profile, {info: 'info'});
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
						assert.deepEqual(info, {info: 'info'});
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

		describe('Not authenticate with fields missing and disabled fallbacks', function authenticateInnerTests() {
			const configureStrategy = (options) => {
				const strategy = new DiscordTokenStrategy(options, () => {});

				sinon
					.stub(strategy._oauth2, 'get')
					.callsFake((_url, _accessToken, next) => next(null, FAKE_PROFILE, null));

				return strategy;
			};

			const cleanupStrategy = (strategy) => {
				strategy._oauth2.get.restore();
			};

			it('Should call fail if neither access token nor refresh token is provided', function test(done) {
				const strategy = configureStrategy({
					...CLIENT_CONFIG,
				});

				chai.passport.use(strategy).fail((error) => {
					assert.typeOf(error, 'object');
					assert.typeOf(error.message, 'string');
					assert.equal(error.message,
						'Neither access token nor refresh token could be parsed from the request');
					done();
				}).authenticate({});

				cleanupStrategy(strategy);
			});

			it('Should call fail if only a refresh token is provided and `refreshTokenFallback` is disabled',
				function test(done) {
					const strategy = configureStrategy({
						...CLIENT_CONFIG,
						refreshTokenFallback: false,
					});

					chai.passport.use(strategy).fail((error) => {
						assert.typeOf(error, 'object');
						assert.typeOf(error.message, 'string');
						assert.equal(error.message,
							'Access token could not be parsed from the request (refresh token exchange disabled)');
						done();
					}).req((req) => {
						req.body = {
							refresh_token: 'refresh_token',
						};
					}).authenticate({});

					cleanupStrategy(strategy);
				});

			it('Should call fail if only a refresh token is provided (with invalid client credentials)',
				function test(done) {
					const strategy = configureStrategy({
						...CLIENT_CONFIG,
					});

					chai.passport.use(strategy).error((error) => {
						assert.instanceOf(error, Error);
						assert.typeOf(error.message, 'string');
						assert.equal(error.message, 'Failed to exchange refresh token for access token');
						assert.typeOf(error.oauthError, 'object');
						assert.typeOf(error.oauthError.statusCode, 'number');
						assert.typeOf(error.oauthError.data, 'string');
						done();
					}).req((req) => {
						req.body = {
							refresh_token: 'refresh_token',
						};
					}).authenticate({});

					cleanupStrategy(strategy);
				});

			it('Should call fail if `req.headers` is not an object',
				function test(done) {
					const strategy = configureStrategy({
						...CLIENT_CONFIG,
					});

					chai.passport.use(strategy).fail((error) => {
						assert.typeOf(error, 'object');
						assert.typeOf(error.message, 'string');
						assert.equal(error.message,
							'Neither access token nor refresh token could be parsed from the request');
						done();
					}).req((req) => {
						req.headers = null;
					}).authenticate({});

					cleanupStrategy(strategy);
				});
		});

		describe('Not authenticate on `_loadUserProfile` errors', function authenticateInnerTests() {
			it('Should call error on `_loadUserProfile` error', function test(done) {
				const strategy = new DiscordTokenStrategy(CLIENT_CONFIG, (accessToken, refreshToken, profile, next) => {
					assert.equal(accessToken, 'access_token');
					assert.equal(refreshToken, 'refresh_token');
					assert.typeOf(profile, 'object');
					assert.typeOf(next, 'function');
					return next(null, profile, {info: 'info'});
				});

				sinon.stub(strategy, '_loadUserProfile')
					.callsFake((_accessToken, next) => next(new Error('Some error occurred')));

				chai.passport.use(strategy).error((error) => {
					assert.instanceOf(error, Error);
					done();
				}).req((req) => {
					req.body = {
						access_token: 'access_token',
						refresh_token: 'refresh_token',
					};
				}).authenticate({});

				strategy._loadUserProfile.restore();
			});
		});
	});

	describe('DiscordTokenStrategy:userProfile', function userProfileTests() {
		it('Should fetch the user profile', function test(done) {
			const strategy = new DiscordTokenStrategy(CLIENT_CONFIG, () => {});
			sinon.stub(strategy._oauth2, 'get').callsFake((_url, _accessToken, next) => next(null, FAKE_PROFILE, null));

			strategy.userProfile('access_token', (error, profile) => {
				if (error) return done(error);

				assert.equal(profile.provider, 'discord');
				assert.equal(profile.id, '268473310986240001');
				assert.equal(profile.username, 'Discord');
				assert.equal(profile.avatar, 'f749bb0cbeeb26ef21eca719337d20f1');
				assert.equal(profile.discriminator, '0001');
				assert.equal(profile.public_flags, '131072');
				assert.typeOf(profile._raw, 'string');

				strategy._oauth2.get.restore();

				done();
			});
		});

		it('Should call error on `_oauth2.get` error', function test(done) {
			const strategy = new DiscordTokenStrategy(CLIENT_CONFIG, () => {});
			sinon.stub(strategy._oauth2, 'get').callsFake((_url, _accessToken, next) => next('Error!'));

			strategy.userProfile('access_token', (error) => {
				assert.instanceOf(error, Error);
				strategy._oauth2.get.restore();
				done();
			});
		});

		it('Should call error for malformed JSON', function test() {
			const strategy = new DiscordTokenStrategy(CLIENT_CONFIG, () => {});
			const malformed = `{${FAKE_PROFILE}`;
			sinon.stub(strategy._oauth2, 'get').callsFake((_url, _accessToken, next) => next(null, malformed, null));

			strategy.userProfile('access_token', (error) => {
				assert.instanceOf(error, Error);
				assert.instanceOf(error, SyntaxError);
				assert.equal(error.message, 'Unexpected token { in JSON at position 1');
			});
		});
	});
});
