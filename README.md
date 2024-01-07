# dns01cf

[![Cloudflare CI/CD](https://github.com/HackThisSite/dns01cf/actions/workflows/cloudflare-cicd.yml/badge.svg?branch=main)](https://github.com/HackThisSite/dns01cf/actions/workflows/cloudflare-cicd.yml)
[![CodeQL](https://github.com/HackThisSite/dns01cf/actions/workflows/github-code-scanning/codeql/badge.svg?branch=main)](https://github.com/HackThisSite/dns01cf/actions/workflows/github-code-scanning/codeql)

## DESCRIPTION

*dns01cf* is a single-file, Wrangler-free Cloudflare Worker that enables ACME DNS-01 validation while protecting your DNS with granular ACLs. Installation takes just a few minutes and can be done directly in the Cloudflare web UI -- no installation of Git, Wrangler, or anything required!

:heavy_check_mark: **Fast Installation**: Deploying *dns01cf* requires only three steps: 1) Create a new Cloudflare API token, 2) Create a new Cloudflare Worker and copy the contents of the [`worker.js`](worker.js) file from this repository into that new Worker, 3) Set the required and any desired optional environment variables, and deploy!

:heavy_check_mark: **Secure DNS**: ACME clients can only modify TXT records strictly within the ACLs you define for each client.

:heavy_check_mark: **Minimal Cloudflare Dependency**: Only one domain needs to be behind Cloudflare, the rest can be anywhere. *dns01cf* is best used with [domain aliasing](https://dan.langille.org/2019/02/01/acme-domain-alias-mode/).

:heavy_check_mark: **Many ACME Clients Supported**: If an ACME client does not yet support *dns01cf*, that's okay! It also supports challenges meant for [acme-dns](https://github.com/joohoi/acme-dns), too!

### WHY?

When using the [ACME protocol](https://en.wikipedia.org/wiki/Automatic_Certificate_Management_Environment) to obtain a free TLS certificate, currently the only challenge type available for wildcard certificates is DNS-01. However this method requires that all ACME clients requesting wildcard certificates be given access to perform DNS changes.

In their documentation for Challenge Types, [Let's Encrypt even states the following risk for DNS-01](https://letsencrypt.org/docs/challenge-types/#dns-01-challenge):

> Keeping API credentials on your web server is risky.

Nearly all DNS providers with APIs give effectively all-or-nothing API access to a whole zone (domain), if not all zones in the account. If an ACME client with DNS API credentials is compromised, all of the zones those API credentials have access to are compromised as well.

Therefore, *dns01cf* was created to enable a more secure means of completing ACME DNS-01 challenges without unnecessarily exposing entire DNS zones to all clients. Furthermore, to make *dns01cf* fast to install and easy to use, it has been kept limited a single file with pure JavaScript and no dependencies while requiring minimal configuration.

### SCENARIOS

*dns01cf* allows you to perform ACME DNS-01 validation across as many domains and sub-domains as you want, provided at least one of your domains is behind Cloudflare. You do not have to move all of your domains behind Cloudflare to use them with *dns01cf*, nor will *dns01cf* need API or other access to any of them. We will use a validation method known as [domain aliasing](https://dan.langille.org/2019/02/01/acme-domain-alias-mode/), where the `_acme-challenge` DNS-01 validation hostname is set as a CNAME that points to another location where the validation will actually occur.

#### One domain behind Cloudflare (Domain Aliasing)

Designate a domain that will act as the central ACME DNS-01 challenge domain. (We will use `dns-domain.com` in our examples.) If you prefer, you can also designate one or more sub-domains where all ACME DNS-01 challenges will be consolidated. (We will use `acme-challenges.dns-domain.com` in our examples.)

Next, setup CNAME DNS entries for all domains and sub-domains that will use *dns01cf*. For example, to validate `foo.bar.example.com` with *dns01cf*, you would add the following CNAME:

    _acme-challenge.foo.bar.example.com  IN CNAME  _acme-challenge.foo.bar.example.com.acme-challenges.dns-domain.com

This looks complicated, so let's break it down:

* *_acme-challenge* - Typical DNS record used for ACME DNS-01 challenges
* *foo.bar.example.com* - The actual hostname to be validated
* *IN CNAME* - The DNS record type to point this to the next part
* *_acme-challenge.foo.bar.example.com* - This will be defined as the ACL in the *dns01cf* client token issued to the ACME client that will request a TLS certificate for *foo.bar.example.com*
* *acme-challenges.dns-domain.com* - This will be defined as the `sub` (subject) in the *dns01cf* client token that all of its ACLs will fall under

You only need to set this DNS CNAME once, then you can define your ACME client token ACLs and subject with granular control over exactly what DNS records each ACME client can modify in a central location.

#### All domains behind Cloudflare

Alternatively, if all of the domains that will use *dns01cf* are behind Cloudflare, then setup is straightforward. Simply ensure the Cloudflare API token that *dns01cf* will use can access all relevant zones.

## DOCUMENTATION

| You can find the full documentation at https://dns01cf.com |
|--|

### INSTALLATION

> These instructions assume you already have an existing Cloudflare account with at least one domain added. We will use `dns-domain.com` in the examples below.

1. First, you will need to generate a Cloudflare API token for *dns01cf* to use. This token will need the following two permissions on the zones you want *dns01cf* to access.
>

    Level: Zone
    Category: DNS
    Access: Edit
 
    Level: Zone
    Category: Zone
    Access: Read

2. Next, create a new Cloudflare Worker for *dns01cf*. Open the Quick Edit editor, clear the contents and copy the contents of the [`worker.js`](worker.js) file in this repository into the editor, then click "Save and deploy".

   *Note: This documentation will assume you named your Cloudflare Worker `dns01cf` and will use an example Worker hostname of `dns01cf.foobar.workers.dev`.*

3. Then navigate to the *dns01cf* Worker Settings tab and add the following three environment variables listed below, as well as any of the optional ones listed on the [documentation site](https://dns01cf.com).

   | NOTICE | It is STRONGLY recommended that you click the **Encrypt** button when adding `CF_API_TOKEN` and `TOKEN_SECRET`, as they contain sensitive information. |
   |--|--|

   `CF_API_TOKEN`

   * Set this to the Cloudflare API token you created a moment ago.

   `TOKEN_SECRET`

   * This is a secret password used by *dns01cf* when generating and validating ACME client tokens. Be sure to remember this secret or store it securely, as you will need it whenever you generate new ACME client tokens.

   `ENABLE_CREATE_TOKEN`

   * This must be set to `true` to enable creating ACME client tokens.

   Now click "Save and deploy".

4. You can optionally enable a scheduled cron job that periodically performs two actions:

   1. Deletes old *dns01cf* DNS records that were not deleted by ACME clients (e.g. when using the `acmedns` listener)
   2. Sends us anonymous telemetry so we can roughly estimate how many people are using *dns01cf*
      * This only sends the current running version of *dns01cf*. You can disable this by setting the `DISABLE_ANON_TELEMETRY` environment variable to `false`.

   It is suggested to schedule this to run every 6 hours.

### USAGE

Note: To create an ACME client token in step one, you must make sure the `ENABLE_CREATE_TOKEN` environment variable is set to `true` as described in [INSTALLATION](#installation) above.

1. Create an ACME client token by sending a *POST* call to `dns01cf.foobar.workers.dev/dns01cf/create_token` (replace `dns01cf.foobar.workers.dev` with your Cloudflare Worker hostname), with a JSON payload like below. You will also need to set an "Authorization" request header with a value of the secret you set for the `TOKEN_SECRET` environment variable in [INSTALLATION](#installation) above. (Do not prefix the value with "Bearer " or anything else.)

    ```json
    {
      "acl": [
        "example.com",
        "sub.example.com",
        "!not-allowed.website.net",
        "*website.net"
      ],
      "aud": "CLOUDFLARE_ZONE_ID",
      "exp": 1234567890,
      "sub": "acme-challenges.dns-domain.com"
    }
    ```

    Only the `acl` list is required, the rest are optional. Each part of that JSON object is as follows:

   `acl`

   * *[REQUIRED]* A list of hostnames where the ACME client is allowed (or specifically not allowed) to set TXT DNS records for ACME DNS-01 challenges.

   Each ACL must be the full hostname of an ACME DNS-01 challenge unless `sub` is set, in which case you can omit the `sub` suffix from your ACLs. You do not need to define the `_acme-challenge.` prefix for each ACL unless the `ACL_STRICT_ACME_HOSTNAME` environment variable is set to `true`. An ACL entry can be prefixed with a `!` to explicitly block an ACME client from modifying it (useful when followed by wildcard ACLs). ACLs are evaluated in order and halt on first match.

    *NOTE:* Wildcards are supported! This uses the [URLPattern API](https://developer.mozilla.org/en-US/docs/Web/API/URL_Pattern_API), however it is strongly recommended that you only use [wildcard tokens](https://developer.mozilla.org/en-US/docs/Web/API/URL_Pattern_API#wildcard_tokens) and not full regular expressions.

    *WARNING:* When using wildcards while `aud` is not defined, be careful if using wildcards in the root domain especially if you have multiple similar domains. For example, if an ACME client has an ACL of "foo*com" and you have domains of foobar.com and foofoo.com, *dns01cf* will choose whichever zone Cloudflare returns first and attempt to assign the DNS record to that zone.

   `aud`

   * *[OPTIONAL]* A single Cloudflare Zone ID which if set will limit the ACME client to only this zone.

   Setting this also improves performance by removing the need for *dns01cf* to perform a Cloudflare Zone ID lookup for each ACME client call.

     *NOTE:* If this is set, `sub` (if also set) must match this zone ID. Otherwise all domains in `acl` must match this zone ID.

   `exp`

   * *[OPTIONAL]* A Unix timestamp (in UTC) when the ACME client token should expire.

   `sub`

   * *[OPTIONAL]* A single hostname containing a valid domain in your Cloudflare account that will act as a prefix for all ACLs and ACME DNS-01 challenges.

   If you have many ACLs all using the same root domain or sub-domain (e.g. `acme-challenges.dns-domain.com`), you can instead simply define that here rather than add it to each ACL entry.

2. When you are finished creating ACME client tokens, you should change the `ENABLE_CREATE_TOKEN` *dns01cf* environment variable to `false` or simply delete it.

3. Configure your ACME client to make a *POST* call to `dns01cf.foobar.workers.dev/dns01cf/set_record` or `dns01cf.foobar.workers.dev/dns01cf/delete_record` (replace `dns01cf.foobar.workers.dev` with your Cloudflare Worker hostname), with a JSON payload like below. Your ACME client will also need to set an "Authorization" request header with a value of `Bearer [token]` (where `[token]` is the ACME client token you generated earlier).

   ```json
   {
     "fqdn": "_acme-challenge.foo.bar.example.com.acme-challenges.dns-domain.com",
     "value": "contents of the ACME DNS-01 challenge"
   }
   ```

   The example above assumes *dns01cf* is using a domain alias setup as described in [SCENARIOS](#scenarios) above.

## ACKNOWLEDGEMENTS

*dns01cf* uses the following softwares and services:

* JavaScript
* Cloudflare
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
