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
 *     clientSecret: DISCORD_CLIENT_SECRET,
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
	 * @param {string} options.clientSecret - client secret of application registered in the Discord Developer Portal
	 * @param {string} [options.accessTokenField='access_token'] - exclude `connections` when fetching profile fields
	 * @param {string} [options.refreshTokenField='refresh_token'] exclude `guilds` when fetching profile fields
	 * @param {Function} verify
	 */
	constructor({
		clientID,
		clientSecret,
		accessTokenField = 'access_token',
		refreshTokenField = 'refresh_token',
		/* Standard Discord OAuth Config */
		authorizationURL = 'https://discord.com/api/oauth2/authorize', // passed to base class
		tokenURL = 'https://discord.com/api/oauth2/token', // passed to base class
		profileURL = 'https://discord.com/api/users/@me',
		connectionsURL = 'https://discord.com/api/users/@me/connections',
		guildsURL = 'https://discord.com/api/users/@me/guilds',
		connectionsScope = 'connections',
		guildsScope = 'guilds',
		...rest // passed to base class
	}, verify) {
		const options = {
			clientID,
			clientSecret,
			authorizationURL,
			tokenURL,
			...rest,
		};

		super(options, verify);

		this.name = 'discord-token';
		this._profileURL = profileURL;
		this._connectionsURL = connectionsURL;
		this._guildsURL = guildsURL;
		this._connectionsScope = connectionsScope;
		this._guildsScope = guildsScope;
		this._accessTokenField = accessTokenField;
		this._refreshTokenField = refreshTokenField;
		this._oauth2.useAuthorizationHeaderforGET(true);
	}

	/**
	 * Authenticates a request by delegating its provided access token to Discord to retrieve the user profile
	 * @param {Object} req = HTTP request object
	 */
	authenticate(req) {
		const accessToken = this.constructor.lookup(req, this._accessTokenField)
			|| this.constructor.parseOAuth2Header(req);
		const refreshToken = this.constructor.lookup(req, this._refreshTokenField);

		if (!accessToken) {
			return this.fail({
				message: `Access token not found in the ${this._accessTokenField} field`,
			});
		}

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
	}

	/**
	 * Retrieve the Discord user profile
	 * @param {String} accessToken
	 * @param {Function} done
	 * TODO: support `connections` and `guilds` scopes as optional fields in the `profile` object
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
	static lookup(req, field) {
		return (req.body && req.body[field])
			|| (req.query && req.query[field])
			|| (req.headers && (req.headers[field] || req.headers[field.toLowerCase()]));
	}

	/**
	 * Parses an OAuth2 RFC6750 bearer authorization token from the headers of a request
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
