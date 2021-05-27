const {OAuth2Strategy, InternalOAuthError} = require('passport-oauth');

/**
 * `DiscordTokenStrategy` for Passport.js.
 *
 * This authentication strategy delegates a provided Discord access token to retrieve a user profile from Discord using
 * the OAuth 2.0 protocol.
 *
 * This strategy is primarily intended for authorizing requests from native clients that have obtained a Discord access
 * token using the Discord Game SDK or the OAuth 2.0 Authorization Code with PKCE flow.
 *
 * @type {DiscordTokenStrategy}
 * @extends OAuth2Strategy
 * @example
 * passport.use(new DiscordTokenStrategy({
 *     clientID: DISCORD_CLIENT_ID,
 * }, (accessToken, refreshToken, profile, done) => {
 *     User.findOrCreate({discordId: profile.id}, (error, user) => {
 *         return done(error, user);
 *     });
 * }));
 */
class DiscordTokenStrategy extends OAuth2Strategy {
	/**
	 * Constructs an instance of the `DiscordTokenStrategy`
	 * @param {Object} options
	 * @param {string} options.clientID - client ID of application registered in the Discord Developer Portal
	 * @param {string} [options.clientSecret] - client secret of application registered in the Discord Developer Portal
	 * @param {string} [options.accessTokenField='access_token'] - the field in which to look up the access token
	 * @param {string} [options.refreshTokenField='refresh_token'] the field in which to look up the refresh token
	 * @param {boolean} [options.checkOAuth2Header] - check for the access token in an OAuth 2.0 `Authorization` header
	 * @param {string[]} [options.lookups] - `req` fields in which to perform token lookups
	 * 										 (defaults: `body`, `query`, `headers`)
	 * @param {...*} [options.rest] - additional arguments to pass to the base `OAuth2Strategy` class
	 * @param {Function} verify
	 */
	constructor({
		clientID,
		clientSecret,
		accessTokenField = 'access_token',
		refreshTokenField = 'refresh_token',
		checkOAuth2Header = true,
		lookups = ['body', 'query', 'headers'],
		...rest // passed to base class
	}, verify) {
		const options = {
			clientID,
			authorizationURL: 'https://discord.com/api/oauth2/authorize',
			tokenURL: 'https://discord.com/api/oauth2/token',
			...rest,
		};

		super(options, verify);

		this.name = 'discord-token';
		/* Strategy Config */
		this._accessTokenField = accessTokenField;
		this._refreshTokenField = refreshTokenField;
		this._lookups = lookups;
		this._checkOAuth2Header = checkOAuth2Header;
		/* Discord OAuth Config */
		this._profileURL = rest._profileURL || 'https://discord.com/api/users/@me';
		this._oauth2.useAuthorizationHeaderforGET(true);
	}

	/**
	 * Authenticates a request by delegating its provided access token to Discord to retrieve the user profile; if an
	 * only a refresh token could be parsed, this method will first attempt to exchange it for an access token
	 * @param {Object} req = HTTP request object
	 */
	authenticate(req) {
		let accessToken = this.lookup(req, this._accessTokenField)
			|| (this._checkOAuth2Header && this.constructor.parseOAuth2Header(req));
		let refreshToken = this.lookup(req, this._refreshTokenField);

		if (!accessToken && !refreshToken) {
			return this.fail({
				message: 'Neither access token nor refresh token could be parsed from the request',
			});
		}

		/* Called once an access token is obtained (either immediately or after refresh token exchange) */
		const loadUserProfile = () => {
			this._loadUserProfile(accessToken, (error, profile) => {
				if (error) return this.error(error);

				const done = (err, user, info) => {
					if (err) return this.error(err);
					if (!user) return this.fail(info);

					return this.success(user, info);
				};

				const args = [accessToken, refreshToken, profile, done];
				if (this._passReqToCallback) args.unshift(req);

				this._verify(...args);
			});
		};

		if (!accessToken && refreshToken) {
			/* Exchange the refresh token */
			return this._oauth2.getOAuthAccessToken(
				refreshToken,
				{grant_type: 'refresh_token'},
				(error, _accessToken, _refreshToken) => {
					if (error) return this.error(error);

					accessToken = _accessToken;
					refreshToken = _refreshToken;

					loadUserProfile();
				},
			);
		}

		loadUserProfile();
	}

	/**
	 * Retrieve the Discord user profile
	 * @param {String} accessToken - access token parsed from the HTTP request
	 * @param {Function} done
	 * TODO: support additional scopes provided to the strategy (e.g. `connections` and `guilds`)
	 */
	userProfile(accessToken, done) {
		this._oauth2.get(this._profileURL, accessToken, (error, body) => {
			if (error) return done(new InternalOAuthError('Failed to fetch user profile', error));

			try {
				const json = JSON.parse(body);

				const profile = {
					provider: 'discord',
					...json,
				};

				done(null, profile);
			} catch (err) {
				done(err);
			}
		});
	}

	/**
	 * Looks up the value of a field within a request; this method checks in order the body, query, and headers of a
	 * request until the value is found
	 * @param {Object} req = HTTP request object
	 * @param {String} field - lookup field
	 * @return {false | String} lookup value for field within the body, query, or headers of the request
	 */
	lookup(req, field) {
		let result;
		this._lookups.find((lookup) => {
			const fields = req[lookup];
			result = (fields && fields[field])
				|| (field === 'headers' && fields[field.toLowerCase()]);

			return result;
		});

		return result;
	}

	/**
	 * Parses an OAuth2 bearer authorization token (RFC6750) from the headers of a request
	 * @param {Object} req = HTTP request object
	 * @return {false | String} bearer authorization token
	 */
	static parseOAuth2Header(req) {
		const headerValue = req.headers && (req.headers.Authorization || req.headers.authorization);

		return headerValue && (() => {
			const bearerRgx = /Bearer (.*)/;
			const match = headerValue.match(bearerRgx);
			return match && match[1];
		})();
	}
}

module.exports = DiscordTokenStrategy;
