'use strict';

var utils = require('./../utils');
var settle = require('./../core/settle');
var buildURL = require('./../helpers/buildURL');
var http = require('http');
var https = require('https');
var httpFollow = require('follow-redirects').http;
var httpsFollow = require('follow-redirects').https;
var url = require('url');
var zlib = require('zlib');
var stream = require('stream');
var pkg = require('./../../package.json');
var createError = require('../core/createError');
var enhanceError = require('../core/enhanceError');
var shouldBypassProxy = require('../helpers/shouldBypassProxy');

/**
 * Drop every `Proxy-Authorization` header from the outgoing header bag,
 * whatever its casing.
 *
 * `Proxy-Authorization` only ever belongs to the hop the request is actually
 * sent to. A value the caller (or a poisoned config) left on the request must
 * never travel to an origin server that is reached directly, and a stale case
 * variant must never survive next to a freshly computed one -- the header bag
 * is a plain object, so `delete headers['Proxy-Authorization']` alone would
 * leave any other casing of the name behind.
 *
 * @param {Object} headers The header bag that is about to be sent
 */
function removeProxyAuthorization(headers) {
  if (!headers) {
    return;
  }

  Object.keys(headers).forEach(function removeHeader(header) {
    if (header.toLowerCase() === 'proxy-authorization') {
      delete headers[header];
    }
  });
}

/**
 * Normalize one half of a host/port pair so a descriptor value (which may be a
 * number, or missing) can be compared with what `url.parse` produced.
 *
 * @param {*} value A host name or a port
 * @returns {string} The comparable form of `value`
 */
function normalizeEndpointPart(value) {
  if (value === null || typeof value === 'undefined') {
    return '';
  }

  return String(value).toLowerCase();
}

/**
 * Keep a `Proxy-Authorization` header on the proxy hop only.
 *
 * The `follow-redirects` release this version depends on exposes no
 * `beforeRedirect` hook: it re-dispatches a redirected request with the very
 * same header bag after overwriting the target protocol, host and port with
 * the redirect target, and it never re-applies the proxy. Credentials computed
 * for the proxy would therefore be sent straight to whatever host an attacker
 * controlled `Location` points at. Wrap the internal re-dispatch -- the wrapper
 * is installed after the first request has already been issued, so only
 * redirect hops go through it -- and drop the header as soon as the hop is no
 * longer addressed to the proxy itself.
 *
 * @param {Object} request The request object returned by the transport
 * @param {*} proxyHost The host the proxy credentials belong to
 * @param {*} proxyPort The port the proxy credentials belong to
 */
function guardRedirectedProxyAuthorization(request, proxyHost, proxyPort) {
  var performRequest = request && request._performRequest;

  // With `maxRedirects: 0` the native transport is used and never redirects.
  if (typeof performRequest !== 'function') {
    return;
  }

  request._performRequest = function performRedirectedRequest() {
    var redirectOptions = this._options || {};
    var redirectHost = redirectOptions.hostname || redirectOptions.host;

    if (normalizeEndpointPart(redirectHost) !== normalizeEndpointPart(proxyHost) ||
        normalizeEndpointPart(redirectOptions.port) !== normalizeEndpointPart(proxyPort)) {
      removeProxyAuthorization(redirectOptions.headers);
    }

    return performRequest.apply(this, arguments);
  };
}

/*eslint consistent-return:0*/
module.exports = function httpAdapter(config) {
  return new Promise(function dispatchHttpRequest(resolve, reject) {
    var data = config.data;
    var headers = config.headers;
    var timer;
    var aborted = false;

    // Set User-Agent (required by some servers)
    // Only set header if it hasn't been set in config
    // See https://github.com/mzabriskie/axios/issues/69
    if (!headers['User-Agent'] && !headers['user-agent']) {
      headers['User-Agent'] = 'axios/' + pkg.version;
    }

    if (data && !utils.isStream(data)) {
      if (Buffer.isBuffer(data)) {
        // Nothing to do...
      } else if (utils.isArrayBuffer(data)) {
        data = new Buffer(new Uint8Array(data));
      } else if (utils.isString(data)) {
        data = new Buffer(data, 'utf-8');
      } else {
        return reject(createError(
          'Data after transformation must be a string, an ArrayBuffer, a Buffer, or a Stream',
          config
        ));
      }

      // Add Content-Length header if data exists
      headers['Content-Length'] = data.length;
    }

    // HTTP basic authentication
    // Every option below is read with an own property check: resolving through
    // `Object.prototype` would let a polluted prototype inject credentials, a
    // proxy, an agent or a serializer into requests the caller never configured.
    var auth = undefined;
    var configAuth = utils.hasOwnProp(config, 'auth') ? config.auth : undefined;
    if (configAuth) {
      var username = configAuth.username || '';
      var password = configAuth.password || '';
      auth = username + ':' + password;
    }

    // Parse url
    var parsed = url.parse(config.url);
    var protocol = parsed.protocol || 'http:';

    if (!auth && parsed.auth) {
      var urlAuth = parsed.auth.split(':');
      var urlUsername = urlAuth[0] || '';
      var urlPassword = urlAuth[1] || '';
      auth = urlUsername + ':' + urlPassword;
    }

    if (auth) {
      delete headers.Authorization;
    }

    var isHttps = protocol === 'https:';
    var agentProp = isHttps ? 'httpsAgent' : 'httpAgent';
    var agent = utils.hasOwnProp(config, agentProp) ? config[agentProp] : undefined;
    var params = utils.hasOwnProp(config, 'params') ? config.params : undefined;
    var paramsSerializer = utils.hasOwnProp(config, 'paramsSerializer') ? config.paramsSerializer : undefined;

    var options = {
      hostname: parsed.hostname,
      port: parsed.port,
      path: buildURL(parsed.path, params, paramsSerializer).replace(/^\?/, ''),
      method: config.method,
      headers: headers,
      agent: agent,
      auth: auth
    };

    var proxy = utils.hasOwnProp(config, 'proxy') ? config.proxy : undefined;
    var location = protocol + '//' + parsed.host + options.path;
    if (!proxy) {
      var proxyEnv = protocol.slice(0, -1) + '_proxy';
      var proxyUrl = process.env[proxyEnv] || process.env[proxyEnv.toUpperCase()];
      if (proxyUrl && !shouldBypassProxy(location)) {
        var parsedProxyUrl = url.parse(proxyUrl);
        proxy = {
          host: parsedProxyUrl.hostname,
          port: parsedProxyUrl.port
        };

        if (parsedProxyUrl.auth) {
          var proxyUrlAuth = parsedProxyUrl.auth.split(':');
          proxy.auth = {
            username: proxyUrlAuth[0],
            password: proxyUrlAuth[1]
          };
        }
      }
    }

    var proxyHost;
    var proxyPort;

    if (!proxy) {
      // No proxy applies to this request: neither an explicit `proxy` config
      // nor a `*_proxy` environment variable, or the target is excluded by
      // `no_proxy`. A `Proxy-Authorization` header left on the request would
      // otherwise be sent straight to the origin server, leaking the proxy
      // credentials to whoever answers it.
      removeProxyAuthorization(options.headers);
    }

    if (proxy) {
      // Every field of the proxy descriptor is read with an own property check.
      // `proxy` is either the object the caller handed to axios or the literal
      // built from the `*_proxy` environment variable above, so both of them
      // resolve missing properties through `Object.prototype`. A polluted
      // prototype would otherwise be able to point the request at a proxy the
      // caller never configured and to inject a `Proxy-Authorization` header,
      // leaking attacker controlled credentials to that proxy.
      proxyHost = utils.hasOwnProp(proxy, 'host') ? proxy.host : undefined;
      proxyPort = utils.hasOwnProp(proxy, 'port') ? proxy.port : undefined;
      options.hostname = proxyHost;
      options.host = proxyHost;
      options.headers.host = parsed.hostname + (parsed.port ? ':' + parsed.port : '');
      options.port = proxyPort;
      options.path = location;

      // Basic proxy authorization
      var proxyAuth = utils.hasOwnProp(proxy, 'auth') ? proxy.auth : undefined;
      if (proxyAuth) {
        var proxyUsername = utils.hasOwnProp(proxyAuth, 'username') ? proxyAuth.username : '';
        var proxyPassword = utils.hasOwnProp(proxyAuth, 'password') ? proxyAuth.password : '';
        var base64 = new Buffer(proxyUsername + ':' + proxyPassword, 'utf8').toString('base64');
        // Drop any caller supplied variant first, so the credentials computed
        // here are the only proxy authorization left in the header bag no
        // matter which casing the caller used.
        removeProxyAuthorization(options.headers);
        options.headers['Proxy-Authorization'] = 'Basic ' + base64;
      }
    }

    var maxRedirects = utils.hasOwnProp(config, 'maxRedirects') ? config.maxRedirects : undefined;
    var transport;
    if (maxRedirects === 0) {
      transport = isHttps ? https : http;
    } else {
      if (maxRedirects) {
        options.maxRedirects = maxRedirects;
      }
      transport = isHttps ? httpsFollow : httpFollow;
    }

    // Create the request
    var req = transport.request(options, function handleResponse(res) {
      if (aborted) return;

      // Response has been received so kill timer that handles request timeout
      clearTimeout(timer);
      timer = null;

      // uncompress the response body transparently if required
      var responseStream = res;
      switch (res.headers['content-encoding']) {
      /*eslint default-case:0*/
      case 'gzip':
      case 'compress':
      case 'deflate':
        // add the unzipper to the body stream processing pipeline
        responseStream = responseStream.pipe(zlib.createUnzip());

        // remove the content-encoding in order to not confuse downstream operations
        delete res.headers['content-encoding'];
        break;
      }

      // return the last request in case of redirects
      var lastRequest = res.req || req;

      var response = {
        status: res.statusCode,
        statusText: res.statusMessage,
        headers: res.headers,
        config: config,
        request: lastRequest
      };

      var maxContentLength = utils.hasOwnProp(config, 'maxContentLength') ? config.maxContentLength : -1;

      if (config.responseType === 'stream') {
        // The streamed response used to be handed straight to the caller, so
        // `maxContentLength` -- enforced on the buffering branch below -- was
        // silently ignored and a hostile server could push an unbounded body
        // into the process. Meter the bytes through a transform instead, and
        // tear the connection down as soon as the limit is passed.
        if (maxContentLength > -1) {
          var streamedBytes = 0;
          var contentLimitExceeded = false;
          var limiter = new stream.Transform({
            transform: function transformResponseChunk(chunk, encoding, callback) {
              streamedBytes += chunk.length;
              if (streamedBytes > maxContentLength) {
                callback(createError('maxContentLength size of ' + maxContentLength + ' exceeded',
                  config, null, lastRequest));
                return;
              }
              callback(null, chunk);
            }
          });

          limiter.on('error', function handleLimiterError() {
            // node 6 has no `stream.destroy()`, but the response always exposes
            // `IncomingMessage#destroy()`, which tears the socket down and stops
            // the server from sending anything else.
            contentLimitExceeded = true;
            res.destroy();
          });

          responseStream.on('error', function handleResponseStreamError(err) {
            if (aborted || contentLimitExceeded) return;
            limiter.emit('error', enhanceError(err, config, null, lastRequest));
          });

          response.data = limiter;
          settle(resolve, reject, response);

          // Defer the pipe so the caller's `then` -- a microtask -- has run and
          // attached its `data`/`error` listeners before any chunk flows through
          // the transform. `process.nextTick` would drain before those
          // microtasks and the error event would be lost.
          setImmediate(function startPipe() {
            responseStream.pipe(limiter);
          });
        } else {
          response.data = responseStream;
          settle(resolve, reject, response);
        }
      } else {
        var responseBuffer = [];
        var totalResponseBytes = 0;
        var bufferLimitExceeded = false;

        responseStream.on('data', function handleStreamData(chunk) {
          if (bufferLimitExceeded) return;
          totalResponseBytes += chunk.length;

          // make sure the content length is not over the maxContentLength if specified
          if (maxContentLength > -1 && totalResponseBytes > maxContentLength) {
            // The buffer used to keep growing after the rejection, so the whole
            // oversized body was still read into memory.
            bufferLimitExceeded = true;
            responseBuffer.length = 0;
            res.destroy();
            reject(createError('maxContentLength size of ' + maxContentLength + ' exceeded',
              config, null, lastRequest));
            return;
          }

          responseBuffer.push(chunk);
        });

        responseStream.on('error', function handleStreamError(err) {
          if (aborted || bufferLimitExceeded) return;
          reject(enhanceError(err, config, null, lastRequest));
        });

        responseStream.on('end', function handleStreamEnd() {
          var responseData = Buffer.concat(responseBuffer);
          if (config.responseType !== 'arraybuffer') {
            responseData = responseData.toString('utf8');
          }

          response.data = responseData;
          settle(resolve, reject, response);
        });
      }
    });

    // A redirect is dispatched by `follow-redirects` with the same header bag,
    // straight at the redirect target instead of at the proxy, so the proxy
    // credentials must not survive the hop.
    guardRedirectedProxyAuthorization(req, proxyHost, proxyPort);

    // Handle errors
    req.on('error', function handleRequestError(err) {
      if (aborted) return;
      reject(enhanceError(err, config, null, req));
    });

    // Handle request timeout
    if (config.timeout && !timer) {
      timer = setTimeout(function handleRequestTimeout() {
        req.abort();
        reject(createError('timeout of ' + config.timeout + 'ms exceeded', config, 'ECONNABORTED', req));
        aborted = true;
      }, config.timeout);
    }

    var cancelToken = utils.hasOwnProp(config, 'cancelToken') ? config.cancelToken : undefined;
    if (cancelToken) {
      // Handle cancellation
      cancelToken.promise.then(function onCanceled(cancel) {
        if (aborted) {
          return;
        }

        req.abort();
        reject(cancel);
        aborted = true;
      });
    }

    // Send the request
    if (utils.isStream(data)) {
      // Neither the native http/https transport nor the follow-redirects
      // release this version depends on caps the size of a streamed request
      // body, so `maxBodyLength` was never honoured and an unbounded upload
      // could be pushed out of the process. Meter the bytes on the way out and
      // abort the request as soon as the limit is passed.
      var maxBodyLength = utils.hasOwnProp(config, 'maxBodyLength') ? config.maxBodyLength : -1;

      if (maxBodyLength > -1) {
        var uploadedBytes = 0;
        var bodyLimitExceeded = false;
        var bodyLimiter = new stream.Transform({
          transform: function transformRequestChunk(chunk, encoding, callback) {
            uploadedBytes += chunk.length;
            if (uploadedBytes > maxBodyLength) {
              callback(createError('Request body larger than maxBodyLength limit', config, null, req));
              return;
            }
            callback(null, chunk);
          }
        });

        bodyLimiter.on('error', function handleBodyLimiterError(err) {
          if (bodyLimitExceeded) return;
          bodyLimitExceeded = true;
          // `pipe` already detached the source when the transform errored; stop
          // writing to the transport too and tear the request down so nothing
          // else leaves the process.
          aborted = true;
          bodyLimiter.unpipe(req);
          req.abort();
          reject(err);
        });

        data.pipe(bodyLimiter).pipe(req);
      } else {
        data.pipe(req);
      }
    } else {
      req.end(data);
    }
  });
};
