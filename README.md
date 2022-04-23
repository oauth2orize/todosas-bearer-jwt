# todosas-bearer-jwt

This app illustrates how to build an OAuth 2.0 server using [Express](https://expressjs.com/),
[OAuth2orize](https://www.oauth2orize.org), and [Passport](https://www.passportjs.org/).
Use this example as a starting point for your own authorization server.

## Quick Start

To run this app, clone the repository and install dependencies:

```bash
$ git clone https://github.com/oauth2orize/todosas-bearer-jwt.git
$ cd todosas-bearer-jwt
$ npm install
```

Then start the server.

```bash
$ npm start
```

## Overview

This example illustrates how to build an OAuth 2.0 authorization server that
supports clients using the web-based authorization code and implicit grants.
The access tokens issued to clients are bearer tokens, the contents of which are
encoded in [JSON Web Token](https://jwt.io/) (JWT) format and compliant with
[RFC 9068](https://datatracker.ietf.org/doc/html/rfc9068).

This app implements sign in and consent functionality.  User interaction is
performed via HTML pages and forms, which are rendered via [EJS](https://ejs.co/)
templates and styled with vanilla CSS.  Data is stored in a [SQLite](https://www.sqlite.org/)
database.

This app exposes OAuth 2.0 endpoints, allowing it to manage access to other apps
and APIs that rely on this server.  This provides the ability to offer single
sign-on (SSO) to a suite of apps and control third-party access to protected
APIs.

## License

[The Unlicense](https://opensource.org/licenses/unlicense)

## Credit

Created by [Jared Hanson](https://www.jaredhanson.me/)
