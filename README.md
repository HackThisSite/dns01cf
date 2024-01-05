# dns01cf

[build status]

## DESCRIPTION

*dns01cf* is a single-file, Wrangler-free CloudFlare Worker that performs ACME DNS-01 validation while protecting your DNS with granular client ACLs. Installation takes under 5 minutes and can be done directly in the CloudFlare web UI -- no installation of Git, Wrangler, or anything required!

:heavy_check_mark: **Fast Installation**: Deploying *dns01cf* requires only three steps: 1) Create a new CloudFlare API token, 2) Create a new CloudFlare Worker and copy the contents of the `worker.js` file from this repository into that new Worker, 3) Set the required and any desired optional environment variables

:heavy_check_mark: **Secure DNS**: ACME clients can only update TXT records strictly within the ACLs you define for each client.

:heavy_check_mark: **Many ACME Clients Supported**: If an ACME client does not yet support *dns01cf*, that's okay! It also supports challenges meant for [acme-dns](https://github.com/joohoi/acme-dns), too!

### WHY?

When using the [ACME protocol](https://en.wikipedia.org/wiki/Automatic_Certificate_Management_Environment) to obtain a free TLS certificate, currently the only challenge type available for wildcard certificates is DNS-01. However this method requires that all ACME clients requesting wildcard certificates be given access to perform DNS changes.

In their documentation for Challenge Types, [Let's Encrypt even states the following risk for DNS-01](https://letsencrypt.org/docs/challenge-types/#dns-01-challenge):

> Keeping API credentials on your web server is risky.

Nearly all DNS providers with APIs give effectively all-or-nothing API access to a whole zone (domain), if not all zones in the account. If an ACME client with DNS API credentials is compromised, all of the zones those API credentials have access to are compromised as well.

## INSTALLATION

### CLOUDFLARE API TOKEN

Create a new CloudFlare API token

### CLOUDFLARE WORKER

Create a new CloudFlare Worker and copy the contents of the `worker.js` file from this repository into that new Worker

### ENVIRONMENT VARIABLES

#### REQUIRED

##### `CF_API_TOKEN`

The CloudFlare API token that will be used by *dns01cf* to perform DNS updates.

##### `TOKEN_SECRET`

The secret used to sign and validate client JWTs.

#### OPTIONAL

##### `ACL_STRICT_ACME_HOSTNAME`

| Default: `false` |
|--|

If set to `true`, ACLs will not implicitly permit an `_acme-challenge.` prefix and each ACL must have this prefix specifically defined, or a wildcard present, for `_acme-challenge.` to be permitted.

##### `API_TIMEOUT`

| Default: `5000` |
|--|

How long in milliseconds to wait for an API call to complete.

##### `DAT_MAX_LENGTH`

| Default: `8192` |
|--|

Maximum length of a `dat` miscellaneous data object in a client JWT.

##### `DISABLE_ANON_TELEMETRY`

| Default: `false` |
|--|

Disable sending anonymous telemetry during cron jobs (only the current running version of *dns01cf* is sent).

If you leave this enabled, thank you! :heart:

##### `DISABLE_POWERED_BY`

| Default: `false` |
|--|

Disable showing an `X-Powered-By` header in responses.

If you leave this enabled, thank you! :heart:

##### `DNS01CF_PATH_PREFIX`

| Default: *(empty)* |
|--|

If set, this prefix will be required on all *dns01cf* listener calls, including `create_token`.

Example:

If `DNS01CF_PATH_PREFIX` is set to `foobar`, then to create a token the path would be `/foobar/dns01cf/create_token`.

##### `ENABLE_CREATE_TOKEN`

| Default: `false` |
|--|

todo

##### `LISTENERS`

| Default: `dns01cf` |
|--|

todo

##### `RECORD_EXPIRATION`

| Default: `86400` |
|--|

todo

##### `RECORD_TTL`

| Default: `60` |
|--|

todo

##### `TOKEN_ALGO`

| Default: `HS256` |
|--|

todo

## USAGE

## ACKNOWLEDGEMENTS

dns01cf uses the following softwares and services:

* CloudFlare
* GitHub
* [tsndr/cloudflare-worker-jwt](https://github.com/tsndr/cloudflare-worker-jwt)

<details>

<summary>LICENSE</summary>

### MIT License

Copyright (c) 2024 HackThisSite

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

</details>
