# Google geo admin tool

This is a little webapp which fetches data via the google admin APIs, specifically login/logout events for users. It then uses the geo databases from MaxMind to check where those events occurred, something which is sorely lacking from the 'native' google admin pages. 

This webapp will request the callers permission to access (read-only) audit reports and usage. 

It also requires a `client_secrets.json` to be provisioned into the docker image, as `/creds/client_secrets.json`. The client secrets file can be downloaded via [google api](https://console.developers.google.com/apis/credentials)

