'use strict';

var urlModule = require('url');
var WhatwgURL = urlModule.URL;

var DEFAULT_PORTS = {
  http: 80,
  https: 443,
  ws: 80,
  wss: 443,
  ftp: 21
};

/**
 * Parses the request location.
 *
 * Node versions that ship the WHATWG `URL` implementation use it, older ones
 * fall back to the legacy parser which exposes the same protocol/hostname/port
 * fields.
 *
 * @param {string} location The absolute request URL
 * @returns {?object} The parsed location or null when it cannot be parsed
 */
function parseLocation(location) {
  if (typeof WhatwgURL === 'function') {
    try {
      return new WhatwgURL(location);
    } catch (err) {
      return null;
    }
  }

  var legacy = urlModule.parse(location);

  return legacy && legacy.protocol && legacy.hostname ? legacy : null;
}

/**
 * Splits a single `no_proxy` entry into its host and port parts.
 *
 * @param {string} entry A single `no_proxy` entry
 * @returns {Array} A [host, port] tuple, port is 0 when unspecified
 */
function parseNoProxyEntry(entry) {
  var entryHost = entry;
  var entryPort = 0;

  if (entryHost.charAt(0) === '[') {
    var bracketIndex = entryHost.indexOf(']');

    if (bracketIndex !== -1) {
      var host = entryHost.slice(1, bracketIndex);
      var rest = entryHost.slice(bracketIndex + 1);

      if (rest.charAt(0) === ':' && /^\d+$/.test(rest.slice(1))) {
        entryPort = parseInt(rest.slice(1), 10);
      }

      return [host, entryPort];
    }
  }

  var firstColon = entryHost.indexOf(':');
  var lastColon = entryHost.lastIndexOf(':');

  if (firstColon !== -1 && firstColon === lastColon && /^\d+$/.test(entryHost.slice(lastColon + 1))) {
    entryPort = parseInt(entryHost.slice(lastColon + 1), 10);
    entryHost = entryHost.slice(0, lastColon);
  }

  return [entryHost, entryPort];
}

/**
 * Splits a dotted-quad IPv4 address into its octets.
 *
 * @param {string} hostname The host to split
 * @returns {?Array} The four octets, or null when the host is not an IPv4 address
 */
function parseIPv4Octets(hostname) {
  var octets = hostname.split('.');

  if (octets.length !== 4) {
    return null;
  }

  for (var i = 0; i < octets.length; i++) {
    if (!/^\d+$/.test(octets[i]) || Number(octets[i]) > 255) {
      return null;
    }
  }

  return octets;
}

/**
 * Rewrites an IPv4-mapped IPv6 host to its plain IPv4 spelling so that the two
 * notations for the same address compare equal.
 *
 * @param {string} hostname The host to normalize
 * @returns {string} The IPv4 spelling, or the host unchanged when it is not IPv4-mapped
 */
// Recognises the canonical IPv4-mapped IPv6 forms the Node URL parser produces:
//   ::ffff:127.0.0.1   (dotted-quad tail)
//   ::ffff:7f00:1      (compressed two-group hex tail)
// Fully-expanded forms like 0:0:0:0:0:ffff:7f00:1 or single-group tails like
// ::ffff:1 are not normalised here. URL inputs are canonicalised by the parser
// before reaching this helper, but hand-crafted no_proxy entries in those
// shapes will not match an IPv4 listing.
function normalizeIPv4MappedIPv6(hostname) {
  // Match against the lowercased form so a hand-crafted no_proxy entry like
  // `[::FFFF:7F00:1]` still resolves to its IPv4 alias. Callers that route via
  // URL parsing already lowercase, but the helper stays robust on its own.
  var lower = hostname.toLowerCase();
  var dottedMatch = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(lower);

  if (dottedMatch) {
    var octets = parseIPv4Octets(dottedMatch[1]);
    return octets ? octets.join('.') : hostname;
  }

  var hexMatch = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(lower);

  if (hexMatch) {
    var high = parseInt(hexMatch[1], 16);
    var low = parseInt(hexMatch[2], 16);

    return [
      (high >> 8) & 0xff,
      high & 0xff,
      (low >> 8) & 0xff,
      low & 0xff
    ].join('.');
  }

  return hostname;
}

/**
 * Removes IPv6 brackets and trailing dots and rewrites IPv4-mapped IPv6 hosts
 * so that equivalent host spellings compare equal.
 *
 * @param {string} host The host to normalize
 * @returns {string} The normalized host
 */
function normalizeNoProxyHost(host) {
  var normalized = host;

  if (!normalized) {
    return normalized;
  }

  if (normalized.charAt(0) === '[' && normalized.charAt(normalized.length - 1) === ']') {
    normalized = normalized.slice(1, -1);
  }

  normalized = normalized.replace(/\.+$/, '');

  return normalizeIPv4MappedIPv6(normalized);
}

/**
 * Determines whether the specified host is an IPv4 loopback address
 *
 * @param {string} host The host to test
 * @returns {boolean} True if the host is within 127.0.0.0/8
 */
function isLoopbackIPv4(host) {
  var octets = host.split('.');

  if (octets.length !== 4) {
    return false;
  }

  if (octets[0] !== '127') {
    return false;
  }

  return octets.every(function testOctet(octet) {
    return /^\d+$/.test(octet) && Number(octet) >= 0 && Number(octet) <= 255;
  });
}

/**
 * Determines whether the specified host refers to the loopback interface
 *
 * The unspecified addresses -- `0.0.0.0` and its IPv6 spelling `::` -- are
 * treated as loopback aliases too. They are only ever a listening wildcard: an
 * outbound connection to either of them is routed to the local host, so a
 * request aimed at `http://0.0.0.0:<port>/` reaches exactly the same service as
 * `http://localhost:<port>/`. Leaving them out of the alias set meant the usual
 * `no_proxy=localhost,127.0.0.1,::1` did not cover them, and a request the
 * caller believed stayed on the loopback interface was sent through the proxy
 * instead -- handing whatever it carried, `Authorization` headers included, to
 * the proxy.
 *
 * @param {string} host The host to test
 * @returns {boolean} True if the host is a loopback alias
 */
function isLoopbackHost(host) {
  return host === 'localhost' || host === '::1' || host === '0.0.0.0' || host === '::' ||
    isLoopbackIPv4(host);
}

/**
 * Determines whether a request to `location` must bypass the configured
 * environment proxy according to the `no_proxy` environment variable.
 *
 * @param {string} location The absolute request URL
 * @returns {boolean} True if the proxy must not be used for this request
 */
module.exports = function shouldBypassProxy(location) {
  var parsed = parseLocation(location);

  if (!parsed) {
    return false;
  }

  var noProxy = (process.env.no_proxy || process.env.NO_PROXY || '').toLowerCase();

  if (!noProxy) {
    return false;
  }

  if (noProxy === '*') {
    return true;
  }

  var protocol = String(parsed.protocol).split(':', 1)[0];
  var port = parsed.port ? parseInt(parsed.port, 10) : (DEFAULT_PORTS[protocol] || 0);
  var hostname = normalizeNoProxyHost(String(parsed.hostname).toLowerCase());

  return noProxy.split(/[\s,]+/).some(function testNoProxyEntry(entry) {
    if (!entry) {
      return false;
    }

    var entryParts = parseNoProxyEntry(entry);
    var entryHost = normalizeNoProxyHost(entryParts[0]);
    var entryPort = entryParts[1];

    if (entryHost === '*') {
      return true;
    }

    if (!entryHost) {
      return false;
    }

    if (entryPort && entryPort !== port) {
      return false;
    }

    if (isLoopbackHost(hostname) && isLoopbackHost(entryHost)) {
      return true;
    }

    if (entryHost.charAt(0) === '*') {
      entryHost = entryHost.slice(1);
    }

    if (entryHost.charAt(0) === '.') {
      return hostname.slice(-entryHost.length) === entryHost;
    }

    return hostname === entryHost;
  });
};
