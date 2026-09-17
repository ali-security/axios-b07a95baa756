'use strict';

var utils = require('../utils');

var INVALID_HEADER_VALUE_RE = /[^\x09\x20-\x7E\x80-\xFF]/g;
var BOUNDARY_WHITESPACE_RE = /^[\x09\x20]+|[\x09\x20]+$/g;

/**
 * Strips characters that are not allowed inside an HTTP header value.
 *
 * CR, LF and NUL let an attacker controlled value break out of the header it
 * belongs to and inject additional headers (or a whole request/response), so
 * they are removed together with the remaining control characters. Leading and
 * trailing spaces/tabs are dropped as well because they are not part of the
 * value per RFC 7230.
 *
 * @param {*} value The header value to sanitize
 * @returns {*} The sanitized header value
 */
function sanitizeHeaderValue(value) {
  if (value === false || value === null || typeof value === 'undefined') {
    return value;
  }

  if (utils.isArray(value)) {
    return value.map(sanitizeHeaderValue);
  }

  var sanitized = String(value).replace(INVALID_HEADER_VALUE_RE, '');

  return sanitized.replace(BOUNDARY_WHITESPACE_RE, '');
}

module.exports = sanitizeHeaderValue;
