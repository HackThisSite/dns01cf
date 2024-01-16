/**
 * dns01cf - CloudFlare Worker for ACME DNS-01 validation with record-level client ACLs
 *
 * Copyright (c) 2024 HackThisSite
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * @version 0.0.2
 * @author dns01cf team <team@dns01cf.com>
 * @see {@link https://dns01cf.com}
 * @format
 * @license MIT
 */

/**
 * dns01cf defaults and config
 * @type {Object}
 */
const DNS01CF = {
  version: "0.0.2",
  urls: {
    website: "https://dns01cf.com",
    github: "https://github.com/dns01d/dns01cf",
    version: "https://dns01cf.com/latest.json",
    telemetry: "https://telemetry.dns01cf.com/send",
    cf_api: "https://api.cloudflare.com/client/v4",
  },
  defaults: {
    ACL_STRICT_ACME_HOSTNAME: false,
    API_TIMEOUT: 5000,
    DAT_MAX_LENGTH: 8192,
    DISABLE_ANON_TELEMETRY: false,
    DISABLE_POWERED_BY: false,
    DNS01CF_PATH_PREFIX: "",
    ENABLE_CREATE_TOKEN: false,
    LISTENERS: "dns01cf",
    RECORD_EXPIRATION: 86400,
    RECORD_TTL: 60,
    TOKEN_ALGO: "HS256",
  },
  config: {},
};

/**
 * HTTP request processor
 * @param {Request} req The incoming HTTP request
 * @param {Object} env The environment bindings assigned to the Worker
 * @param {Object} ctx Context accessor to augment or control how the request is handled
 * @returns {Promise<Response>} HTTP Response object
 */
async function processRequest(req, env, ctx) {
  const { pathname } = new URL(req.url);
  // 204 empty responses
  const null_paths = [undefined, null, "/", "/favicon.ico"];
  if (null_paths.includes(pathname)) {
    return dns01cfResponse(null, { status: 204 });
  } else if (pathname === "/robots.txt") {
    const newline = String.fromCharCode(10);
    return dns01cfResponse(`User-agent: *${newline}Disallow: /`);
  }

  // Preflight check for proper configs
  try {
    preFlightCheck(env);
  } catch (e) {
    return dns01cfError(`Configuration error: ${e.message}. Config docs can be found at: ${DNS01CF.urls.website}`, {
      status: 500,
    });
  }

  // Run through all defined listeners
  try {
    const l = new Listener();
    const res = await l.process(req, env);
    if (res && res instanceof Response) return res;
  } catch (e) {
    const [, lineno, colno] = e.stack.match(/(\d+):(\d+)/);
    return dns01cfError(`Runtime error (line ${lineno} col ${colno}): ${e.message}`, { status: 500 });
  }

  // 404 catch-all
  return dns01cfResponse(null, { status: 404 });
}

/**
 * Cron event processor
 * @param {ScheduledEvent} event Event object
 * @param {Object} env An object containing the bindings associated with this worker
 * @param {Object} ctx An object containing the context associated with this worker
 */
async function processCron(event, env, ctx) {
  // Preflight check for proper configs
  try {
    preFlightCheck(env);
  } catch (e) {
    const msg = `Configuration error: ${e.message}. Config docs can be found at: ${DNS01CF.urls.website}`;
    console.error(msg);
    return new Response(msg, { status: 500 });
  }

  let cf_zones = [];
  try {
    if (DNS01CF.config.CF_ZONE_ID) {
      const cf_zone = await CFAPI.getZoneByID(DNS01CF.config.CF_ZONE_ID);
      cf_zones.push(cf_zone);
    } else {
      cf_zones = await CFAPI.listZones();
    }
    for (let z in cf_zones) {
      const del = await CFAPI.deleteOldRecords(cf_zones[z].id);
      for (let d in del) {
        const exp = new Date(del[d].expiry);
        console.log(`TXT record deleted: '${del[d].name}' = '${del[d].content}' (Expired ${exp.toISOString()})`);
      }
    }
  } catch (e) {
    console.error(`API error: ${e.message}`);
    return new Response(`API error: ${e.message}`, { status: 500 });
  }

  /**
   * Send anonymous telemetry to dns01cf (thank you if you do!)
   * This only sends the current running version and nothing else.
   */
  if (!DNS01CF.config.DISABLE_ANON_TELEMETRY) {
    try {
      await fetch(DNS01CF.urls.telemetry, {
        signal: AbortSignal.timeout(DNS01CF.config.API_TIMEOUT),
        method: "POST",
        body: JSON.stringify({
          version: `dns01cf-v${DNS01CF.version}`,
        }),
      });
    } catch (e) {
      console.warn(`Unable to send telemetry: ${e.message}`);
    }
  }

  return new Response("OK");
}

/**
 * Preflight check of all systems before powering the Worker on
 * Also sets the dns01cf config to environment bindings or defaults
 * @param {Object} env The environment bindings assigned to the Worker
 * @throws {Error} Thrown when environment bindings are missing or invalid
 */
function preFlightCheck(env) {
  // TOKEN_SECRET
  if (!env.TOKEN_SECRET) {
    throw new Error("Missing 'TOKEN_SECRET'");
  } else {
    DNS01CF.config.TOKEN_SECRET = env.TOKEN_SECRET;
  }
  // CF_API_TOKEN
  if (!env.CF_API_TOKEN) {
    throw new Error("Missing 'CF_API_TOKEN'");
  } else {
    DNS01CF.config.CF_API_TOKEN = env.CF_API_TOKEN;
  }
  // TOKEN_ALGO
  if (env.TOKEN_ALGO) {
    const algos = Object.keys(AuthToken.algos);
    if (algos.includes(env.TOKEN_ALGO)) {
      DNS01CF.config.TOKEN_ALGO = env.TOKEN_ALGO;
    } else {
      throw new Error("Invalid setting for 'TOKEN_ALGO'");
    }
  } else {
    DNS01CF.config.TOKEN_ALGO = DNS01CF.defaults.TOKEN_ALGO;
  }
  // LISTENERS
  if (env.LISTENERS) {
    const listeners = String(env.LISTENERS).split(",");
    for (let l of listeners) if (!Listener.listeners.includes(l)) throw new Error("Invalid setting for 'LISTENERS'");
    DNS01CF.config.LISTENERS = env.LISTENERS;
  } else {
    DNS01CF.config.LISTENERS = DNS01CF.defaults.LISTENERS;
  }
  // - DNS01CF_PATH_PREFIX
  DNS01CF.config.DNS01CF_PATH_PREFIX = env.DNS01CF_PATH_PREFIX ?? DNS01CF.defaults.DNS01CF_PATH_PREFIX;
  // API_TIMEOUT
  if (env.API_TIMEOUT) {
    if (isNaN(env.API_TIMEOUT)) throw new Error("'API_TIMEOUT' must be a number");
    DNS01CF.config.API_TIMEOUT = parseInt(env.API_TIMEOUT, 10);
  } else {
    DNS01CF.config.API_TIMEOUT = DNS01CF.defaults.API_TIMEOUT;
  }
  // DAT_MAX_LENGTH
  if (env.DAT_MAX_LENGTH) {
    if (isNaN(env.DAT_MAX_LENGTH)) throw new Error("'DAT_MAX_LENGTH' must be a number");
    DNS01CF.config.DAT_MAX_LENGTH = parseInt(env.DAT_MAX_LENGTH, 10);
  } else {
    DNS01CF.config.DAT_MAX_LENGTH = DNS01CF.defaults.DAT_MAX_LENGTH;
  }
  // RECORD_TTL - Must come before RECORD_EXPIRATION
  if (env.RECORD_TTL) {
    if (isNaN(env.RECORD_TTL)) throw new Error("'RECORD_TTL' must be a number");
    const record_ttl = parseInt(env.RECORD_TTL, 10);
    if (record_ttl < 60 || record_ttl !== 1 || record_ttl > 86400)
      throw new Error("'RECORD_TTL' must be between 60 and 86400, or set to 1 for automatic");
    DNS01CF.config.RECORD_TTL = record_ttl;
  } else {
    DNS01CF.config.RECORD_TTL = DNS01CF.defaults.RECORD_TTL;
  }
  // RECORD_EXPIRATION - Must come after RECORD_TTL
  if (env.RECORD_EXPIRATION) {
    if (isNaN(env.RECORD_EXPIRATION)) throw new Error("'RECORD_EXPIRATION' must be a number");
    const record_exp = parseInt(env.RECORD_EXPIRATION, 10);
    if (record_exp < DNS01CF.config.RECORD_TTL || record_exp > 86400)
      throw new Error(`'RECORD_EXPIRATION' must be between ${DNS01CF.config.RECORD_TTL} and 86400`);
    DNS01CF.config.RECORD_EXPIRATION = record_exp;
  } else {
    DNS01CF.config.RECORD_EXPIRATION = DNS01CF.defaults.RECORD_EXPIRATION;
  }
  // CF_ZONE_ID
  if (env.CF_ZONE_ID) {
    if (String(env.CF_ZONE_ID).length > 32 || env.CF_ZONE_ID.match(/[^0-9a-z]/i))
      throw new Error("'CF_ZONE_ID' is too long or has invalid characters");
    DNS01CF.config.CF_ZONE_ID = env.CF_ZONE_ID;
  }
  // DISABLE_ANON_TELEMETRY
  DNS01CF.config.DISABLE_ANON_TELEMETRY = env.DISABLE_ANON_TELEMETRY
    ? String(env.DISABLE_ANON_TELEMETRY).toLowerCase() === "true"
    : DNS01CF.defaults.DISABLE_ANON_TELEMETRY;
  // DISABLE_POWERED_BY
  DNS01CF.config.DISABLE_POWERED_BY = env.DISABLE_POWERED_BY
    ? String(env.DISABLE_POWERED_BY).toLowerCase() === "true"
    : DNS01CF.defaults.DISABLE_POWERED_BY;
  // ACL_STRICT_ACME_HOSTNAME
  DNS01CF.config.ACL_STRICT_ACME_HOSTNAME = env.ACL_STRICT_ACME_HOSTNAME
    ? String(env.ACL_STRICT_ACME_HOSTNAME).toLowerCase() === "true"
    : DNS01CF.defaults.ACL_STRICT_ACME_HOSTNAME;
  // ENABLE_CREATE_TOKEN
  DNS01CF.config.ENABLE_CREATE_TOKEN = env.ENABLE_CREATE_TOKEN
    ? String(env.ENABLE_CREATE_TOKEN).toLowerCase() === "true"
    : DNS01CF.defaults.ENABLE_CREATE_TOKEN;
  // CF_API_URL - For CI override tests
  if (env.CF_API_URL) {
    try {
      const url = new URL(env.CF_API_URL);
      if (!url) throw new Error("'CF_API_URL' is invalid");
    } catch (e) {
      throw new Error(`'CF_API_URL' is invalid: ${e.message}`);
    }
    DNS01CF.urls.cf_api = env.CF_API_URL;
  }
}

/**
 * dns01cf HTTP response
 * @param {any} [body] A String or Object that defines the body content for the response
 * @param {ResponseInit} [init] An object that contains custom settings to apply to the response
 * @param {Object} [json_settings] Object of JSON settings
 * @param {Boolean} [json_settings.json=false] If set to True, process this response as JSON
 * @param {Boolean} [json_settings.pretty=false] If set to True, print human-readable prettified JSON
 * @returns {Response} HTTP Response object
 */
function dns01cfResponse(body = null, init = {}, json_settings = { json: false, pretty: false }) {
  if (!init.headers) init.headers = {};
  init.headers["Expires"] = new Date(1).toUTCString();
  init.headers["Last-Modified"] = new Date().toUTCString();
  init.headers["Cache-Control"] = "max-age=0, no-cache, must-revalidate, proxy-revalidate";
  if (!DNS01CF.config.DISABLE_POWERED_BY)
    init.headers["X-Powered-By"] = `dns01cf v${DNS01CF.version} - ${DNS01CF.urls.website}`;
  if (json_settings.json) {
    return json_settings.pretty ? new Response(JSON.stringify(body, null, 2), init) : Response.json(body, init);
  } else {
    return new Response(body, init);
  }
}

/**
 * dns01cf HTTP response
 * @param {String} message A String or Object that defines the body content for the response
 * @param {ResponseInit} [init] An object that contains custom settings to apply to the response
 * @returns {Response} HTTP Response object
 */
function dns01cfError(message, init = {}) {
  if (!init.status) init.status = 500;
  return dns01cfResponse({ result: "error", message: message }, init, { json: true, pretty: true });
}

/**
 * Zone object for CFAPI
 * @typedef {Object} CFZone
 * @property {String} id CloudFlare zone identifier
 * @property {String} name Zone domain name
 */

/**
 * Record object for CFAPI
 * @typedef {Object} CFRecord
 * @property {String} id CloudFlare record identifier
 * @property {String} type Record type
 * @property {Number} ttl Record TTL
 * @property {Number} expiry Record expiration Unix timestamp
 * @property {String} name Record hostname
 * @property {String} content Record content
 */

/**
 * CloudFlare API Model
 * @class
 */
class CFAPI {
  /**
   *
   * @param {String} path CloudFlare API path
   * @param {Object} init Settings for fetch() call
   * @throws {Error} Thrown on invalid and error responses from the CloudFlare API
   * @returns {Promise<Array|Object>} Contents of the `result` object from a successful JSON response
   */
  static async _call(path, init = {}) {
    const url = `${DNS01CF.urls.cf_api}${path}`;
    init.signal = AbortSignal.timeout(DNS01CF.config.API_TIMEOUT);
    if (!init.headers) init.headers = {};
    init.headers["Authorization"] = `Bearer ${DNS01CF.config.CF_API_TOKEN}`;
    const result = await fetch(url, init);
    let res;
    try {
      res = await result.json();
    } catch (e) {
      const body = await result.text();
      throw new Error(`[CFAPI] Error parsing response as JSON: ${e.message}; Body returned: ${body}`);
    }
    if (!result.ok) {
      if (res.errors) {
        let errors = [];
        for (let e in res.errors) {
          errors.push(res.errors[e].message);
        }
        throw new Error(errors.join("; "));
      } else {
        const json = JSON.stringify(res);
        throw new Error(`[CFAPI] Unparseable error during response. JSON returned: ${json}`);
      }
    }
    if (typeof res.result !== "undefined") return res.result;
    // If we made it this far, we got a very unexpected response from Cloudflare
    const json = JSON.stringify(res);
    throw new Error(`[CFAPI] Received OK response but no result object returned. JSON returned: ${json}`);
  }

  /**
   * List all Cloudflare zones available to us
   * @throws {Error} Thrown on invalid and error responses from the CloudFlare API
   * @returns {Promise<CFZone[]>} List of zone IDs and their domain names
   */
  static async listZones() {
    const res = await this._call("/zones");
    let zones = [];
    for (let z in res) {
      zones.push({ id: res[z].id, name: res[z].name });
    }
    return zones;
  }

  /**
   * Get a zone by ID
   * @param {String} zoneID Cloudflare zone identifier
   * @returns {Promise<CFZone>} The zone ID and hostname
   */
  static async getZoneByID(zoneID) {
    const res = await this._call(`/zones/${zoneID}`);
    if (typeof res.id === "undefined") return null;
    return { id: res.id, name: res.name };
  }

  /**
   * Get a zone by hostname
   * @param {String} name The hostname to lookup in Cloudflare
   * @param {Boolean} [exactMatch] If false, will check if `name` ends with any zones returned by Cloudflare, otherwise will be an exact match
   * @returns {Promise<CFZone>} The zone ID and hostname
   */
  static async getZoneByName(name, exactMatch = false) {
    const zones = await CFAPI.listZones();
    for (let zone of zones) {
      if ((exactMatch && name === zone.name) || !exactMatch || name.endsWith(zone.name))
        return { id: zone.id, name: zone.name };
    }
    return null;
  }

  /**
   *
   * @param {String} zoneID
   * @param {String} record
   * @param {String} content
   * @throws {Error}
   * @returns {Promise<CFRecord>}
   */
  static async setRecord(zoneID, record, content) {
    const expiry = Math.floor(Date.now() / 1000) + DNS01CF.config.RECORD_EXPIRATION;
    const comment = [
      "MANAGED BY DNS01CF, DO NOT MODIFY",
      JSON.stringify({
        ver: DNS01CF.version,
        set: Math.floor(Date.now() / 1000),
        exp: expiry,
      }),
      "dns01cf",
    ];
    const init = {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        proxied: false,
        comment: comment.join("!"),
        ttl: DNS01CF.config.RECORD_TTL,
        type: "TXT",
        name: record,
        content: content,
      }),
    };
    const res = await this._call(`/zones/${zoneID}/dns_records`, init);
    return {
      id: res.id,
      type: res.type,
      ttl: res.ttl,
      expiry: expiry,
      name: res.name,
      content: res.content,
    };
  }

  // May be used, todo
  static validatedns01cfRecord(record) {
    if (typeof record[0] === "undefined" || !record[0].name) {
      throw new Error(`Record is invalid`);
    } else if (record.length !== 1) {
      throw new Error(`Received ${record.length} records, expected only exactly one`);
    }
    const rec = record[0];
    const comment = rec.comment.split("!");
    if (comment.length === 3 && String(comment[2]) === "dns01cf") {
      try {
        const json = JSON.parse(comment[1]);
        if (json.exp) {
          return true;
        } else {
          throw new Error("Missing field: exp");
        }
      } catch (e) {
        return false;
      }
    }
    return false;
  }

  /**
   *
   * @param {String} zoneID
   * @param {String} record
   * @param {String} content
   * @param {Boolean} [skipLookup]
   * @throws {Error}
   * @returns {Promise<CFRecord>}
   */
  static async deleteRecordByValue(zoneID, record, content, skipLookup = false) {
    const record_enc = encodeURI(record);
    const content_enc = encodeURI(content);
    const res_find = await this._call(
      `/zones/${zoneID}/dns_records?match=all&type=TXT&comment.endswith=%21dns01cf&name=${record_enc}&content=${content_enc}`,
    );
    if (typeof res_find[0] === "undefined" || !res_find[0].name) {
      throw new Error(`Cannot find TXT record matching '${record}' = '${content}'`);
    } else if (res_find.length !== 1) {
      throw new Error(`Received ${res_find.length} records, expected only exactly one`);
    }
    const rec = res_find[0];
    const comment = rec.comment.split("!");
    if (comment.length === 3 && String(comment[2]) === "dns01cf") {
      try {
        const json = JSON.parse(comment[1]);
        if (json.exp) {
          const res_del = await this._call(`/zones/${zoneID}/dns_records/${rec.id}`, { method: "DELETE" });
          if (typeof res_del.id === "undefined" || !res_del.id)
            throw new Error("DNS record delete call failed, nothing returned");
          return {
            id: res_del.id,
            type: rec.type,
            ttl: rec.ttl,
            expiry: json.exp,
            name: record,
            content: content,
          };
        } else {
          throw new Error("Missing field: exp");
        }
      } catch (e) {
        console.warn(`Record '${rec.name}' seems to have been set by dns01cf but its metadata is corrupted.`);
        console.warn(`  JSON parse error: ${e.message}`);
        console.warn(`  Metadata (Record comment): ${rec.comment}`);
      }
    }
  }

  /**
   *
   * @param {String} zoneID
   * @throws {Error}
   * @returns {Promise<Array>}
   */
  static async deleteOldRecords(zoneID) {
    const res_find = await this._call(`/zones/${zoneID}/dns_records?match=all&type=TXT&comment.endswith=%21dns01cf`);
    let deleted = [];
    for (let rec of res_find) {
      const comment = rec.comment.split("!");
      if (comment.length === 3 && String(comment[2]) === "dns01cf") {
        try {
          const json = JSON.parse(comment[1]);
          if (json.exp >= Math.floor(Date.now() / 1000)) {
            const res_del = await this._call(`/zones/${zoneID}/dns_records/${rec.id}`, { method: "DELETE" });
            deleted.push({
              id: rec.id,
              type: rec.type,
              ttl: rec.ttl,
              expiry: json.exp,
              name: rec.name,
              content: rec.content,
            });
          }
        } catch (e) {
          console.warn(`Record '${rec.name}' seems to have been set by dns01cf but its metadata is corrupted.`);
          console.warn(`  JSON parse error: ${e.message}`);
          console.warn(`  Metadata (Record comment): ${rec.comment}`);
        }
      }
    }
    return deleted;
  }
}

/**
 * dns01cf listeners
 * @class
 */
class Listener {
  /**
   * Process an HTTP request
   * @param {Request} request HTTP request
   * @param {Object} env The environment bindings assigned to the Worker
   */
  async process(request, env) {
    this.req = request;
    this.env = env;
    const { pathname } = new URL(request.url);
    this.pathname = pathname;
    const listeners = String(DNS01CF.config.LISTENERS).split(",");
    for (let l of listeners) {
      if (Object.keys(this.listener_funcs).includes(l)) {
        const res = await this.listener_funcs[l](request, env);
        if (res) return res;
      }
    }
    return false;
  }

  /**
   * Test if the current request matches a URLPattern pathname test
   * @param {Request} request The current Request
   * @param {String} path A URLPattern pathname to test
   * @returns {URLPatternURLPatternResult} Result of the test if passed, else null
   */
  static testPath(request, path) {
    const { pathname } = new URL(request.url);
    const pathtest = new URLPattern({ pathname: path });
    if (pathtest.test({ pathname: pathname }))
      return pathtest.exec({ pathname: pathname });
    return null;
  }

  /**
   * Static list of all listeners, used for fast preFlightCheck()
   * @static
   */
  static listeners = ["dns01cf", "acmedns"];

  /**
   * Listener functions
   */
  listener_funcs = {
    /**
     * Listener for dns01cf (including create_token)
     * @param {Request} req HTTP request
     * @param {Object} env The environment bindings assigned to the Worker
     * @returns {Promise<Response>} Parsed FQDN hostname and TXT record value to set
     */
    dns01cf: async function (req, env) {
      // Test path, otherwise return null
      const pathres = Listener.testPath(req, "/:prefix?/dns01cf/:action(set_record|delete_record|create_token)");
      if (!pathres || req.method !== "POST") return null;
      // Test DNS01CF_PATH_PREFIX if test
      if (DNS01CF.config.DNS01CF_PATH_PREFIX || pathres.pathname.groups.prefix)
        if (pathres.pathname.groups.prefix !== DNS01CF.config.DNS01CF_PATH_PREFIX) return null;
      // Extract Authorization header content
      const authheader = req.headers.get("authorization");
      if (!authheader) return dns01cfError("Missing 'Authorization' header", { status: 401 });
      const bearertoken = authheader.split(" ");
      const authtok = new AuthToken(DNS01CF.config.TOKEN_SECRET, env);
      let json; // JSON body
      let zone_id; // CF Zone ID
      // Extract JSON
      try {
        json = await req.json();
      } catch (e) {
        return dns01cfError(`Invalid JSON: ${e.message}`, { status: 400 });
      }
      switch (pathres.pathname.groups.action) {
        // Create a new dns01cf JWT
        case "create_token":
          let payload = {};
          // Tests:
          // - Is create_token endpoint enabled?
          if (!DNS01CF.config.ENABLE_CREATE_TOKEN)
            return dns01cfError(
              "This endpoint is disabled. Set 'ENABLE_CREATE_TOKEN' to 'true' to enable this endpoint. " +
                `Config docs can be found at: ${DNS01CF.urls.website}`,
              { status: 403 },
            );
          // - Does the Authorization header match TOKEN_SECRET?
          if (authheader !== DNS01CF.config.TOKEN_SECRET)
            return dns01cfError("Invalid token secret", { status: 403 });
          // - JWT expiration
          if (typeof json.exp !== "undefined") {
            if (typeof json.exp !== "number" || json.exp <= Math.floor(Date.now() / 1000))
              return dns01cfError("'exp' must be an integer Unix timestamp set to a future time", { status: 400 });
            payload.exp = json.exp;
          }
          // - JWT audience
          let cf_zone; // Confirmed associated CF Zone ID
          if (json.aud) {
            // Check syntax
            if (json.aud.length > 32 || json.aud.match(/[^0-9a-z]/i))
              return dns01cfError("'aud' is too long or has invalid characters", { status: 400 });
            zone_id = json.aud;
            payload.aud = json.aud;
          } else if (DNS01CF.config.CF_ZONE_ID) {
            zone_id = DNS01CF.config.CF_ZONE_ID;
          }
          // - Test CF Zone ID extracted from either `aud` or CF_ZONE_ID
          if (zone_id) {
            try {
              cf_zone = await CFAPI.getZoneByID(zone_id);
            } catch (e) {
              return dns01cfError(`Error validating Zone ID '${zone_id}': ${e.message}`, { status: 422 });
            }
          }
          // - Extract out zone info for Subject and ACL tests
          let cf_zones = []; // Zones to test
          if (cf_zone) {
            cf_zones.push(cf_zone);
          } else {
            try {
              cf_zones = await CFAPI.listZones();
            } catch (e) {
              return dns01cfError(`Unable to list zones: ${e.message}`, { status: 422 });
            }
          }
          // - JWT subject
          if (json.sub) {
            // Hostname valid
            if (!authtok.testHostname(json.sub))
              return dns01cfError("'sub' is not a valid hostname", { status: 422 });
            let z = 0,
              found = false,
              hostnames = [];
            // Find which CF Zone matches the JWT subject
            while (cf_zones[z] && found === false) {
              const p = new URLPattern({ hostname: `{:subdomain.}*${cf_zones[z].name}` });
              if (p.test({ hostname: json.sub })) found = true;
              hostnames.push(cf_zones[z].name);
              z++;
            }
            // No match, return an error
            if (!found)
              return dns01cfError(
                `'sub' error: Hostname '${json.sub}' does not have a matching zone. ` +
                  `Zone hostnames returned from CloudFlare: ${hostnames.join(", ")}`,
                { status: 422 },
              );
            payload.sub = json.sub;
          }
          // - ACL
          if (!json.acl) return dns01cfError("'acl' is required", { status: 400 });
          try {
            authtok.testACL(json.acl);
          } catch (e) {
            return dns01cfError(`'acl' syntax error: ${e.message}`, { status: 400 });
          }
          if (!payload.sub) {
            for (let acl of json.acl) {
              if (String(acl).startsWith("!")) acl = String(acl).substring(1);
              const p_acl = new URLPattern({ hostname: acl });
              let z = 0,
                found = false,
                hostnames = [];
              while (cf_zones[z] && found === false) {
                const p_zone = new URLPattern({ hostname: `{:subdomain.}*${cf_zones[z].name}` });
                if (
                  p_zone.test({ hostname: acl }) ||
                  p_acl.test({ hostname: cf_zones[z].name }) ||
                  p_acl.test({ hostname: `.${cf_zones[z].name}` })
                )
                  found = true;
                hostnames.push(cf_zones[z].name);
                z++;
              }
              if (!found)
                return dns01cfError(
                  "When 'sub' is not set, all ACLs must have a defined CloudFlare zone. " +
                    `ACL '${acl}' does not have a matching zone. ` +
                    `Zone hostnames returned from CloudFlare: ${hostnames.join(", ")}`,
                  { status: 422 },
                );
            }
          }
          payload.acl = json.acl;
          // - Other data (client name, comments, etc.)
          if (json.dat) {
            const len = JSON.stringify(json.dat).length;
            if (len > DNS01CF.config.DAT_MAX_LENGTH)
              return dns01cfError(
                `'dat' cannot exceed ${DNS01CF.config.DAT_MAX_LENGTH} bytes in size. Current size: ${len}`,
                { status: 422 },
              );
            payload.dat = json.dat;
          }
          // End Tests
          // Generate and return a new token
          const newtok = await authtok.generateToken(payload);
          const newtok_decoded = authtok.decodeToken(newtok);
          return dns01cfResponse(
            {
              result: "ok",
              message: "Token generated",
              token: newtok,
              payload: newtok_decoded.payload,
            },
            { status: 200 },
            { json: true, pretty: true },
          );
          break;
        // Set or delete a DNS record
        case "set_record":
        case "delete_record":
          const set_action = pathres.pathname.groups.action === "set_record";
          const testFQDN = authtok.testHostname(json.fqdn);
          if (!json.fqdn || !testFQDN)
            return dns01cfError("Missing or invalid JSON parameter: fqdn", { status: 400 });
          if (!json.value) return dns01cfError("Missing or invalid JSON parameter: value", { status: 400 });
          if (bearertoken.length !== 2)
            return dns01cfError("Missing or invalid 'Authorization: Bearer' token", { status: 403 });
          try {
            const acl_valid = await authtok.validateTokenAccess(bearertoken[1], json.fqdn);
            if (!acl_valid) return dns01cfError(`Not authorized for FQDN: ${json.fqdn}`, { status: 403 });
          } catch (e) {
            return dns01cfError(`Invalid token: ${e.message}`, { status: 403 });
          }
          const tok_parts = authtok.decodeToken(bearertoken[1]);
          // Get CloudFlare Zone ID
          try {
            zone_id = tok_parts.aud || DNS01CF.config.CF_ZONE_ID || (await CFAPI.getZoneByName(json.fqdn));
          } catch (e) {
            return dns01cfError(`Unable to list zones: ${e.message}`, { status: 500 });
          }
          if (!zone_id)
            return dns01cfError(
              "Token 'aud' and config 'CF_ZONE_ID' not set, and unable to find " +
                `CloudFlare Zone ID for ${json.fqdn} from API lookup`,
              { status: 500 },
            );
          let actres;
          try {
            actres = set_action
              ? await CFAPI.setRecord(zone_id, json.fqdn, json.value)
              : await CFAPI.deleteRecordByValue(zone_id, json.fqdn, json.value);
          } catch (e) {
            return dns01cfError(`Error during DNS update: ${e.message}`, { status: 500 });
          }
          return dns01cfResponse(
            {
              result: "ok",
              message: set_action
                ? `'${json.fqdn}' set to value '${json.value}'`
                : `'${json.fqdn}' with value '${json.value}' deleted`,
              response: actres,
            },
            { status: 200 },
            { json: true },
          );
          break;
        default:
          return null;
      }
    },

    /**
     * Listener for acmedns
     * @param {Request} req HTTP request
     * @param {Object} env The environment bindings assigned to the Worker
     * @returns {Promise<Response>} Parsed FQDN hostname and TXT record value to set
     */
    acmedns: async function (req, env) {
      // Test path, otherwise return null
      const pathres = Listener.testPath(req, "/update");
      if (!pathres || req.method !== "POST") return null;
      const authheader = req.headers.get("x-api-key");
      if (!authheader) return dns01cfError("Missing 'X-API-Key' header", { status: 401 });
      const authtok = new AuthToken(DNS01CF.config.TOKEN_SECRET, env);
      let json;
      try {
        json = await req.json();
      } catch (e) {
        return dns01cfError(`Invalid JSON: ${e.message}`, { status: 400 });
      }

      const testSubdomain = authtok.testHostname(json.subdomain);
      if (!json.subdomain || !testSubdomain)
        return dns01cfError("Missing or invalid JSON parameter: subdomain", { status: 400 });
      if (!json.txt) return dns01cfError("Missing or invalid JSON parameter: txt", { status: 400 });
      try {
        const acl_valid = await authtok.validateTokenAccess(authheader, json.subdomain);
        if (!acl_valid) return dns01cfError(`Not authorized for Subdomain: ${json.subdomain}`, { status: 403 });
      } catch (e) {
        return dns01cfError(`Invalid token: ${e.message}`, { status: 403 });
      }
      const tok_parts = authtok.decodeToken(authheader);
      // Get CloudFlare Zone ID
      let zone_id;
      try {
        zone_id = tok_parts.aud || DNS01CF.config.CF_ZONE_ID || (await CFAPI.getZoneByName(json.subdomain));
      } catch (e) {
        return dns01cfError(`Unable to list zones: ${e.message}`, { status: 500 });
      }
      if (!zone_id)
        return dns01cfError(
          "Token 'aud' and config 'CF_ZONE_ID' not set, and unable to find " +
            `CloudFlare Zone ID for ${json.subdomain} from API lookup`,
          { status: 500 },
        );
      let actres;
      try {
        actres = await CFAPI.setRecord(zone_id, json.subdomain, json.txt);
      } catch (e) {
        return dns01cfError(`Error during DNS update: ${e.message}`, { status: 500 });
      }
      return dns01cfResponse(
        {
          result: "ok",
          message: `'${json.subdomain}' set to value '${json.txt}'`,
          response: actres,
        },
        { status: 200 },
        { json: true },
      );
    },
  };
}

/**
 * dns01cf JWT class
 * Borrowed heavily from the project linked below
 * @see {@link https://github.com/tsndr/cloudflare-worker-jwt}
 * @class
 */
class AuthToken {
  /**
   * Supported algorithms
   */
  static algos = {
    HS256: { name: "HMAC", hash: { name: "SHA-256" } },
    HS384: { name: "HMAC", hash: { name: "SHA-384" } },
    HS512: { name: "HMAC", hash: { name: "SHA-512" } },
  };

  /**
   * @constructs AuthToken
   * @param {String} secret JWT secret
   * @param {Object} env The environment bindings assigned to the Worker
   */
  constructor(secret, env) {
    this.secret = secret;
    this.env = env;
    this.algoname = DNS01CF.config.TOKEN_ALGO;
    this.algo = AuthToken.algos[this.algoname];
  }

  /**
   * Validate the authenticity of a dns01cf JWT
   * @param {String} token The JWT to validate
   * @throws {Error} Thrown if the JWT does not meet proper specifications or, if defined, when `nbf` or `exp` are invalid
   * @returns {Promise<Boolean>} Returns True if signature passes, otherwise returns False
   */
  async validateToken(token) {
    if (typeof token !== "string") throw new Error("JWT must be a String");
    const tokenParts = token.split(".");
    if (tokenParts.length !== 3) throw new Error("Invalid JWT structure");
    const { headers, payload } = this.decodeToken(token);
    if (!headers || !payload) throw new Error("Error parsing JWT");
    if (!headers.typ || !headers.alg || headers.typ.toUpperCase() !== "JWT") throw new Error("Invalid headers");
    if (!Object.keys(AuthToken.algos).includes(headers.alg.toUpperCase())) throw new Error("Invalid algorithm");
    if (payload.nbf && payload.nbf > Math.floor(Date.now() / 1000)) throw new Error("Token not yet valid");
    if (payload.exp && payload.exp <= Math.floor(Date.now() / 1000)) throw new Error("Token expired");
    if (!payload.acl) throw new Error("Missing ACL");
    this.testACL(payload.acl);
    const key = await this.importKey();
    return await crypto.subtle.verify(
      this.algo,
      key,
      this.base64UrlToArrayBuffer(tokenParts[2]),
      this.textToArrayBuffer(`${tokenParts[0]}.${tokenParts[1]}`),
    );
  }

  /**
   * Generate a dns01cf JWT
   * @param {Object} payload
   * @returns {Promise<String>} JSON Web Token
   */
  async generateToken(payload) {
    payload.iss = `dns01cf_v${DNS01CF.version}`;
    payload.iat = payload.nbf = Math.floor(Date.now() / 1000);
    const key = await this.importKey();
    const header = { typ: "JWT", alg: this.algoname };
    const headerB64 = this.textToBase64Url(JSON.stringify(header));
    const payloadB64 = this.textToBase64Url(JSON.stringify(payload));
    const signature = await crypto.subtle.sign(this.algo, key, this.textToArrayBuffer(`${headerB64}.${payloadB64}`));
    const signatureB64 = this.arrayBufferToBase64Url(signature);
    return `${headerB64}.${payloadB64}.${signatureB64}`;
  }

  /**
   * Decodes a JWT WITHOUT verifying its validity first
   * @param {String} token
   * @returns {Object} JWT payload
   */
  decodeToken(token) {
    const parts = token.split(".");
    try {
      return {
        headers: JSON.parse(this.base64UrlToText(parts[0])),
        payload: JSON.parse(this.base64UrlToText(parts[1])),
      };
    } catch {
      return false;
    }
  }

  /**
   * Import the JWT key
   * @returns {Promise<CryptoKey>}
   */
  async importKey() {
    return await crypto.subtle.importKey("raw", this.textToArrayBuffer(this.secret), this.algo, true, ["verify", "sign"]);
  }

  /**
   * Validate a token and its ACL against an FQDN
   * @param {String} token JWT to validate
   * @param {String} fqdn FQDN to validate against the token's ACL
   * @throws {Error} Thrown if the token is invalid
   * @returns {Promise<Boolean>} True if permitted, False if not permitted
   */
  async validateTokenAccess(token, fqdn) {
    const valid = await this.validateToken(token);
    if (!valid) throw new Error("Invalid token signature");
    const tok = this.decodeToken(token);
    if (tok.payload.sub && !this.testHostname(tok.payload.sub)) throw new Error("Invalid token subject");
    for (let acl of tok.payload.acl) {
      const host = tok.payload.sub ? `${acl}.${tok.payload.sub}` : acl;
      if (host.startsWith("!")) {
        if (this.testHostnamePattern(host.substring(1), fqdn)) return false;
      } else {
        if (this.testHostnamePattern(host, fqdn)) return true;
      }
      // If ACL_STRICT_ACME_HOSTNAME is not enabled, also implicitly grant and test an `_acme-challenge.` prefix on the ACL
      if (!DNS01CF.config.ACL_STRICT_ACME_HOSTNAME) {
        if (host.startsWith("!")) {
          if (this.testHostnamePattern(`_acme-challenge.${host.substring(1)}`, fqdn)) return false;
        } else {
          if (this.testHostnamePattern(`_acme-challenge.${host}`, fqdn)) return true;
        }
      }
    }
    return false;
  }

  /**
   * Test an ACL for validity
   * @param {Object} acl The ACL to test
   * @throws {Error} Thrown if the ACL is invalid
   * @returns {Boolean} True if valid
   */
  testACL(acl) {
    if (typeof acl !== "object" || Object.prototype.toString.call(acl) !== "[object Array]")
      throw new Error("ACL must be a list of FQDNs");
    if (acl.length === 0) throw new Error("ACL cannot be an empty list");
    for (let fqdn of acl) {
      if (!this.testACLHostname(fqdn)) throw new Error(`Invalid ACL FQDN syntax: ${fqdn}`);
    }
    return true;
  }

  /**
   * Test that a hostname is a proper FQDN, also allowing for asterisk wildcards and exlamation negation
   * Also allows for an underscore prefix for `_acme-challenge`
   * @param {String} hostname Hostname to test
   * @returns {Boolean} Result of the test
   */
  testACLHostname(hostname) {
    return new RegExp("^(?=^.{4,253}.?$)(^_?((?!-)!?[a-zA-Z0-9-*]{1,63}(?<!-).)+[a-zA-Z*]{2,63}$)$", "g").test(
      hostname,
    );
  }

  /**
   * Test that a hostname is a proper FQDN
   * Also allows for an underscore prefix for `_acme-challenge`
   * @param {String} hostname Hostname to test
   * @returns {Boolean} Result of the test
   */
  testHostname(hostname) {
    return new RegExp("^(?=^.{4,253}.?$)(^_?((?!-)[a-zA-Z0-9-]{1,63}(?<!-).)+[a-zA-Z]{2,63}$)$", "g").test(hostname);
  }

  /**
   * Test a URLPattern hostname against another hostname
   * @param {String} pattern A hostname for URLPattern
   * @param {String} hostname The hostname to test
   * @returns {Boolean} The result of URLPattern.test()
   */
  testHostnamePattern(pattern, hostname) {
    const p = new URLPattern({ hostname: pattern });
    return p.test({ hostname: hostname });
  }

  /**
   * @param {Uint8Array} bytes
   * @returns {String}
   */
  bytesToByteString(bytes) {
    let byteStr = "";
    for (let i = 0; i < bytes.byteLength; i++) {
      byteStr += String.fromCharCode(bytes[i]);
    }
    return byteStr;
  }

  /**
   * @param {String} byteStr
   * @returns {Uint8Array}
   */
  byteStringToBytes(byteStr) {
    let bytes = new Uint8Array(byteStr.length);
    for (let i = 0; i < byteStr.length; i++) {
      bytes[i] = byteStr.charCodeAt(i);
    }
    return bytes;
  }

  /**
   * @param {String} str
   * @returns {String}
   */
  base64UrlToText(str) {
    return atob(str.replace(/-/g, "+").replace(/_/g, "/"));
  }

  /**
   * @param {String} str
   * @returns {String}
   */
  textToBase64Url(str) {
    return btoa(str).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
  }

  /**
   * @param {ArrayBuffer} arrayBuffer
   * @returns {String}
   */
  arrayBufferToBase64String(arrayBuffer) {
    return btoa(this.bytesToByteString(new Uint8Array(arrayBuffer)));
  }

  /**
   * @param {ArrayBuffer} arrayBuffer
   * @returns {String}
   */
  arrayBufferToBase64Url(arrayBuffer) {
    return this.arrayBufferToBase64String(arrayBuffer).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
  }

  /**
   * @param {String} b64str
   * @returns {ArrayBuffer}
   */
  base64StringToArrayBuffer(b64str) {
    return this.byteStringToBytes(atob(b64str)).buffer;
  }

  /**
   * @param {String} b64url
   * @returns {ArrayBuffer}
   */
  base64UrlToArrayBuffer(b64url) {
    return this.base64StringToArrayBuffer(b64url.replace(/-/g, "+").replace(/_/g, "/").replace(/\s/g, ""));
  }

  /**
   * @param {String} str
   * @returns {ArrayBuffer}
   */
  textToArrayBuffer(str) {
    return this.byteStringToBytes(decodeURI(encodeURIComponent(str)));
  }
}

/**
 * JavaScript module export for this dns01cf CloudFlare Worker
 */
export default {
  /**
   * CloudFlare Worker event handler for an HTTP fetch event
   * @param {Request} req The incoming HTTP request
   * @param {Object} env The environment bindings assigned to the Worker
   * @param {Object} ctx Context accessor to augment or control how the request is handled
   * @returns {Promise<Response>} HTTP Response object
   */
  async fetch(req, env, ctx) {
    return await processRequest(req, env, ctx);
  },

  /**
   * CloudFlare Worker event handler for scheduled cron events
   * @param {ScheduledEvent} event Event object
   * @param {Object} env An object containing the bindings associated with this worker
   * @param {Object} ctx An object containing the context associated with this worker
   */
  async scheduled(event, env, ctx) {
    ctx.waitUntil(processCron(event, env, ctx));
  },
};

/** dns01cf - EOF */
