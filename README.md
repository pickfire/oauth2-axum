Oauth2 axum example
===================

This repo contains examples for using OAuth2 authentication in an axum application.

Current versions:

- oauth2 5.0.0-alpha.4
- axum 0.7.5

Running
-------

Example provided for google, credentials available at
https://console.developers.google.com/apis/credentials

    GOOGLE_CLIENT_ID=xxx GOOGLE_CLIENT_SECRET=yyy cargo run
    x-www-browser http://127.0.0.1:5000/
