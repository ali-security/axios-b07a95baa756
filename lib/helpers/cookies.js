'use strict';

var utils = require('./../utils');

module.exports = (
  utils.isStandardBrowserEnv() ?

  // Standard browser envs support document.cookie
  (function standardBrowserEnv() {
    return {
      write: function write(name, value, expires, path, domain, secure) {
        var cookie = [];
        cookie.push(name + '=' + encodeURIComponent(value));

        if (utils.isNumber(expires)) {
          cookie.push('expires=' + new Date(expires).toGMTString());
        }

        if (utils.isString(path)) {
          cookie.push('path=' + path);
        }

        if (utils.isString(domain)) {
          cookie.push('domain=' + domain);
        }

        if (secure === true) {
          cookie.push('secure');
        }

        document.cookie = cookie.join('; ');
      },

      read: function read(name) {
        // Match `name=value` by splitting on the semicolon separator instead of building a
        // RegExp from `name`: interpolating an unescaped name into a RegExp lets
        // metacharacters (e.g. `.*` or a nested quantifier such as `(a+)+b`) match the wrong
        // cookie or trigger catastrophic backtracking, and an invalid pattern (e.g. `[`)
        // throws a SyntaxError. Browsers serialize cookie pairs as either ';' or '; ', so
        // leading whitespace is skipped before each cookie name.
        var cookies = document.cookie.split(';');
        var cookie;
        var separatorIndex;

        for (var i = 0; i < cookies.length; i++) {
          cookie = cookies[i].replace(/^\s+/, '');
          separatorIndex = cookie.indexOf('=');
          if (separatorIndex !== -1 && cookie.slice(0, separatorIndex) === name) {
            return decodeURIComponent(cookie.slice(separatorIndex + 1));
          }
        }

        return null;
      },

      remove: function remove(name) {
        this.write(name, '', Date.now() - 86400000);
      }
    };
  })() :

  // Non standard browser env (web workers, react-native) lack needed support.
  (function nonStandardBrowserEnv() {
    return {
      write: function write() {},
      read: function read() { return null; },
      remove: function remove() {}
    };
  })()
);
