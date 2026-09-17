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

    if (proxy) {
      options.hostname = proxy.host;
      options.host = proxy.host;
      options.headers.host = parsed.hostname + (parsed.port ? ':' + parsed.port : '');
      options.port = proxy.port;
      options.path = location;

      // Basic proxy authorization
      if (proxy.auth) {
        var base64 = new Buffer(proxy.auth.username + ':' + proxy.auth.password, 'utf8').toString('base64');
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
