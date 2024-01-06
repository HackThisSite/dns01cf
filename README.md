# dns01cf

[build status]

| NOTE: This documentation is a work-in-progress and is not yet complete! |
|--|

## DESCRIPTION

*dns01cf* is a single-file, Wrangler-free CloudFlare Worker that performs ACME DNS-01 validation for domains behind CloudFlare while protecting your account with granular client ACLs. Installation takes under 5 minutes and can be done directly in the CloudFlare web UI -- no installation of Git, Wrangler, or anything required!

:heavy_check_mark: **Fast Installation**: Deploying *dns01cf* requires only three steps: 1) Create a new CloudFlare API token, 2) Create a new CloudFlare Worker and copy the contents of the `worker.js` file from this repository into that new Worker, 3) Set the required and any desired optional environment variables

:heavy_check_mark: **Secure DNS**: ACME clients can only update TXT records strictly within the ACLs you define for each client.

:heavy_check_mark: **Many ACME Clients Supported**: If an ACME client does not yet support *dns01cf*, that's okay! It also supports challenges meant for [acme-dns](https://github.com/joohoi/acme-dns), too!

### WHY?

When using the [ACME protocol](https://en.wikipedia.org/wiki/Automatic_Certificate_Management_Environment) to obtain a free TLS certificate, currently the only challenge type available for wildcard certificates is DNS-01. However this method requires that all ACME clients requesting wildcard certificates be given access to perform DNS changes.

In their documentation for Challenge Types, [Let's Encrypt even states the following risk for DNS-01](https://letsencrypt.org/docs/challenge-types/#dns-01-challenge):

> Keeping API credentials on your web server is risky.

Nearly all DNS providers with APIs give effectively all-or-nothing API access to a whole zone (domain), if not all zones in the account. If an ACME client with DNS API credentials is compromised, all of the zones those API credentials have access to are compromised as well. This is true for CloudFlare API tokens as well.

Therefore, *dns01cf* was created to provide a single-file, Wrangler-free CloudFlare Worker solution that performs ACME DNS-01 validation for domains behind CloudFlare while protecting your account with granular client ACLs.

## INSTALLATION

These instructions assume you already have an existing CloudFlare account with at least one domain added.

### CLOUDFLARE API TOKEN

First, you will need to generate a CloudFlare API token for *dns01cf* to use. This token will need the following two permissions on the zones you want *dns01cf* to access.

    Level: Zone
    Category: DNS
    Access: Edit

    Level: Zone
    Category: Zone
    Access: Read

<details>

<summary>Detailed instructions</summary>

1. Login to your [CloudFlare dashboard](https://dash.cloudflare.com)
2. Navigate to [User API Tokens](https://dash.cloudflare.com/profile/api-tokens)
3. Click the **Create Token** button
4. Click the **Use template** button next to "Edit zone DNS"
5. Under "Permissions" leave the first permission as "Zone", "DNS", "Edit"
6. Then click **+ Add more**
    * In the new dropdowns select in order: "Zone", "Zone", "Read"
7. Under "Zone Resources" change this to the zones you want *dn01cf* to access
8. Click the **Continue to summary** button
9. Make sure everything looks correct then click the **Create Token** button
10. Copy the API token it gives you. **Do not lose this token, it is only shown once!**

</details>

### CLOUDFLARE WORKER

Create a new CloudFlare Worker, open the Quick Edit editor, clear the contents and copy the contents of the [`worker.js`](worker.js) file in this repository into the CloudFlare editor, save and deploy.

<details>

<summary>Detailed instructions</summary>

1. Login to your [CloudFlare dashboard](https://dash.cloudflare.com)
2. Navigate to **Workers & Pages**
   * Hint: Halfway down the left menu before you select any of your domains
3. Click the **Create application** button
4. Click the **Create Worker** button
5. Give the worker a name (for example, `dns01cf`), then click the **Deploy** button
6. Next, click the **Edit code** button
   * If you click **Configure Worker**, that's okay. Just click the **Quick edit** button in the upper-right corner.
7. Clear out the entire contents of the `worker.js` file that opens in the editor
8. Copy the entire contents of the [`worker.js`](worker.js) file in this repository into the CloudFlare editor from the prior step
    * Note: Make sure that everything from the license comment at the top to the `/** dns01cf - EOF */` comment at the bottom was copied
9. Click the **Save and deploy** button in the upper-right corner, and again in the popup dialog
    * Note: If this button is grayed out, add then remove an extra blank line at the botton of the file and wait a moment for the button to become active
10. In the upper-left corner underneath of the CloudFlare logo, click the name of your *dns01cf* application to return to your CloudFlare dashboard

</details>

### ENVIRONMENT VARIABLES

Add the two required environment variables listed below, as well as any of the optional ones listed further down, save and deploy.

<details>

<summary>Detailed instructions</summary>

1. Login to your [CloudFlare dashboard](https://dash.cloudflare.com)
2. Navigate to **Workers & Pages**
   * Hint: Halfway down the left menu before you select any of your domains
3. Click on the *dns01cf* application you created from the [CLOUDFLARE WORKER](#cloudflare-worker) instructions above
4. Click the **Settings** tab in the middle of the page, then click the **Variables** tab in the center-left of the page
5. Add the two required environment variables listed below, as well as any of the optional ones listed further down
   * Note: It is *STRONGLY* recommended that you click the **Encrypt** button when adding the required environment variable that contain sensitive information
6. Click the **Save and deploy** button

</details>

#### REQUIRED

##### `CF_API_TOKEN`

The CloudFlare API token that will be used by *dns01cf* to perform DNS updates.

You can find instructions for creating this token above in the [CLOUDFLARE API TOKEN](#cloudflare-api-token) section.

| NOTICE | It is STRONGLY recommended that you click the **Encrypt** button when adding this environment variable. |
|--|--|

##### `TOKEN_SECRET`

The secret used to sign and validate client JWTs.

| NOTICE | It is STRONGLY recommended that you click the **Encrypt** button when adding this environment variable. |
|--|--|

#### OPTIONAL

<details>

<summary>Click to expand</summary>

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

Must be set to `true` in order to use the `create_token` endpoint. For security this is not enabled by default.

##### `LISTENERS`

| Default: `dns01cf` |
|--|

A comma-delimited list of listeners to enable for clients to use, evaluated in order of first to last.

Supported listeners:

* `dns01cf`
* `acmedns`

##### `RECORD_EXPIRATION`

| Default: `86400` |
|--|

How long a TXT record should last for before the cron job is permitted to prune it.

Used when [LISTENERS](#LISTENERS) contains `acmedns`.

Must be no less than the setting of [RECORD_TTL](#RECORD-TTL) and no greater than 86400.

##### `RECORD_TTL`

| Default: `60` |
|--|

The TTL value for a TXT record. Must be between 60 and 86400.

##### `TOKEN_ALGO`

| Default: `HS256` |
|--|

Algorithm to use when generating a client JWT.

Supported algorithms:

* `HS256`
* `HS384`
* `HS512`

</details>

### (OPTIONAL) CRON JOB

You can optionally enable a scheduled cron job that periodically performs two actions:

1. Deletes old *dns01cf* DNS records that were not deleted by ACME clients (e.g. when using the `acmedns` [listener](#listeners))
2. Sends us anonymous telemetry so we can roughly estimate how many people are using *dns01cf*
   * Note: This only sends the current running version of *dns01cf*. You can disable this by setting the [DISABLE_ANON_TELEMETRY](#disable_anon_telemetry) environment variable in the [OPTIONAL](#optional) section above.

It is suggested to schedule this to run every 6 hours.

<details>

<summary>Detailed instructions</summary>

1. Login to your [CloudFlare dashboard](https://dash.cloudflare.com)
2. Navigate to **Workers & Pages**
   * Hint: Halfway down the left menu before you select any of your domains
3. Click on the *dns01cf* application you created from the [CLOUDFLARE WORKER](#cloudflare-worker) instructions above
4. Click the **Triggers** tab in the middle of the page, then scroll down to the "Cron Triggers" section
5. Click the **Add Cron Trigger** button
6. Change the "Execute Worker every" dropdowns to "Hour(s)" and "6"
   * Hint: The "Cron" field below should show `0 */6 * * *`
7. Click the **Add Trigger** button

</details>

## USAGE

### 1. CREATE CLIENT TOKEN

*todo*

### 2. CONFIGURE CLIENT

*todo*

### 3. ACME CHALLENGE

*todo*

## ACKNOWLEDGEMENTS

*dns01cf* uses the following softwares and services:

* JavaScript
* CloudFlare
* GitHub
* Parts of [tsndr/cloudflare-worker-jwt](https://github.com/tsndr/cloudflare-worker-jwt)

## LICENSE

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
