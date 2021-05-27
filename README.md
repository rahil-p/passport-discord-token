# passport-discord-token

Passport strategy for authorizing users with Discord access tokens using the OAuth 2.0 API.

This module lets you authenticate using Discord in your Node.js applications. 
By plugging into Passport, Discord 
authentication can be easily and unobtrusively integrated into any application or framework that supports Connect-style
middleware, including Express.

[![npm](https://img.shields.io/npm/v/passport-discord-token?logo=npm)](https://www.npmjs.com/package/passport-discord-token)
[![codecov](https://codecov.io/gh/rahil-p/passport-discord-token/branch/master/graph/badge.svg?token=LSOQ2ZCWIS)](https://codecov.io/gh/rahil-p/passport-discord-token)

---
<a name="note"></a>

**Note:**

This strategy is primarily intended for authorizing requests from native clients that must obtain a Discord access
token using client-side flows (e.g. Discord Game SDK, PKCE) before authenticating with your Node.js backend. 

For browser clients, a strategy like [passport-discord](https://github.com/nicholastay/passport-discord.git) is better
suited.

---

[comment]: <> (![Build Status]&#40;https://img.shields.io/travis/drudge/passport-discord-token.svg&#41;)
[comment]: <> (![Coverage]&#40;https://img.shields.io/coveralls/drudge/passport-discord-token.svg&#41;)

## Installation
```shell
npm install passport-discord-token
```
```shell
yarn add passport-discord-token
```

## Usage

### Create an Application
Before using `passport-discord-token`, you must register an application with Discord.  If you have not already done so,
create an application in the <a href="https://discord.com/developers/applications" target="_blank">Discord Developer Portal</a>.
Your application will be issued a client ID, which needs to be provided to the strategy.

### Configure Strategy

The strategy requires a `verify` callback, which accepts these credentials and calls `done` providing a `user`, as well
as options specifying a `clientID`.

```js
const DiscordTokenStrategy = require('passport-discord-token');

passport.use(new DiscordTokenStrategy({
    clientID: DISCORD_CLIENT_ID,
    clientSecret: DISCORD_CLIENT_SECRET,
}, (accessToken, refreshToken, profile, done) => {
    User.findOrCreate({discordId: profile.id}, (error, user) => {
        return done(error, user);
    });
}));
```

### Authenticate Requests

Use `passport.authenticate()`, specifying the `'discord-token'` strategy, to authenticate requests.

For example, as route middleware in an Express application:

```js
app.post('/auth/discord-token', 
    passport.authenticate('discord-token'),
    (req, res) => {
        res.send(req.user ? 200 : 401);
    });
```

## Client-Side

### Configure Client
Your client must first obtain an access token from Discord's OAuth 2.0 endpoints before making a request to this
strategy ([_see note_](#note)). Here are some options:

[**Discord Game SDK**](https://discord.com/developers/docs/game-sdk/sdk-starter-guide) - Call
  [`ApplicationManager.GetOAuth2Token`](https://discord.com/developers/docs/game-sdk/applications#getoauth2token) to
  obtain a token directly from your game.

[**Authorization Code Flow**](https://discord.com/developers/docs/topics/oauth2#authorization-code-grant)
  
- **with PKCE** ([RFC7636](https://datatracker.ietf.org/doc/html/rfc7636)) - A secure means for obtaining an access
  token from a native client. _Although this modified flow is supported by Discord's API, documentation is pending._

[**Implicit Grant**](https://discord.com/developers/docs/topics/oauth2#implicit-grant)

### Client Requests

Clients can send a request to a route that uses the `passport-discord-token` strategy by providing an access token in
the request's body, query parameters, or headers.

**Body:**
```shell
POST /auth/discord-token
access_token=<TOKEN>
```

**Query Parameter:**
```shell
GET /auth/discord-token?access_token=<TOKEN>
```

**Authorization Header:**
```shell
GET /auth/discord-token
Authorization: Bearer <TOKEN>
```

## License
[MIT License](https://github.com/rahil-p/passport-discord-token/blob/master/LICENSE)
