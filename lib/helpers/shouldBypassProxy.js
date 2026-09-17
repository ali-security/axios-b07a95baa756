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
 * Removes IPv6 brackets and trailing dots so that equivalent host spellings
 * compare equal.
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

  return normalized.replace(/\.+$/, '');
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
 * @param {string} host The host to test
 * @returns {boolean} True if the host is a loopback alias
 */
function isLoopbackHost(host) {
  return host === 'localhost' || host === '::1' || isLoopbackIPv4(host);
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
