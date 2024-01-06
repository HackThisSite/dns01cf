# dns01cf

---

> CloudFlare Worker for ACME DNS-01 validation with granular client ACLs

| NOTE: This documentation site is a work-in-progress and is not yet complete! |
|--|

## What is *dns01cf*?

*dns01cf* is a single-file, Wrangler-free CloudFlare Worker that performs ACME DNS-01 validation for domains behind CloudFlare while protecting your account with granular client ACLs. Installation takes under 5 minutes and can be done directly in the CloudFlare web UI -- no installation of Git, Wrangler, or anything required!

:heavy_check_mark: **Fast Installation**: Deploying *dns01cf* requires only three steps: 1) Create a new CloudFlare API token, 2) Create a new CloudFlare Worker and copy the contents of the `worker.js` file from this repository into that new Worker, 3) Set the required and any desired optional environment variables

:heavy_check_mark: **Secure DNS**: ACME clients can only update TXT records strictly within the ACLs you define for each client.

:heavy_check_mark: **Many ACME Clients Supported**: If an ACME client does not yet support *dns01cf*, that's okay! It also supports challenges meant for [acme-dns](https://github.com/joohoi/acme-dns), too!

## Why is *dns01cf* needed?

When using the [ACME protocol](https://en.wikipedia.org/wiki/Automatic_Certificate_Management_Environment) to obtain a free TLS certificate, currently the only challenge type available for wildcard certificates is DNS-01. However this method requires that all ACME clients requesting wildcard certificates be given access to perform DNS changes.

In their documentation for Challenge Types, [Let's Encrypt even states the following risk for DNS-01](https://letsencrypt.org/docs/challenge-types/#dns-01-challenge):

> Keeping API credentials on your web server is risky.

Nearly all DNS providers with APIs give effectively all-or-nothing API access to a whole zone (domain), if not all zones in the account. If an ACME client with DNS API credentials is compromised, all of the zones those API credentials have access to are compromised as well. This is true for CloudFlare API tokens as well.

Therefore, *dns01cf* was created to provide a single-file, Wrangler-free CloudFlare Worker solution that performs ACME DNS-01 validation for domains behind CloudFlare while protecting your account with granular client ACLs.

## Documentation

See the menu on the left.

## Acknowledgements

*dns01cf* uses the following softwares and services:

* JavaScript
* CloudFlare
* GitHub
* Parts of [tsndr/cloudflare-worker-jwt](https://github.com/tsndr/cloudflare-worker-jwt)

## License

*dns01cf* &copy; 2024 HackThisSite, licensed under the [MIT License](license.md).
