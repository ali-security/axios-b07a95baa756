'use strict';

var utils = require('./../utils');
var settle = require('./../core/settle');
var buildURL = require('./../helpers/buildURL');
var parseHeaders = require('./../helpers/parseHeaders');
var isURLSameOrigin = require('./../helpers/isURLSameOrigin');
var createError = require('../core/createError');
var btoa = (typeof window !== 'undefined' && window.btoa && window.btoa.bind(window)) || require('./../helpers/btoa');

module.exports = function xhrAdapter(config) {
  return new Promise(function dispatchXhrRequest(resolve, reject) {
    var requestData = config.data;
    var requestHeaders = config.headers;
    // Options that decide where credentials go are read with an own property
    // check so a polluted `Object.prototype` cannot opt the request into
    // sending the xsrf token or cookies to a foreign origin.
    var withXSRFToken = utils.hasOwnProp(config, 'withXSRFToken') ? config.withXSRFToken : undefined;
    var xsrfHeaderName = utils.hasOwnProp(config, 'xsrfHeaderName') ? config.xsrfHeaderName : undefined;
    var xsrfCookieName = utils.hasOwnProp(config, 'xsrfCookieName') ? config.xsrfCookieName : undefined;

    if (utils.isFormData(requestData)) {
      delete requestHeaders['Content-Type']; // Let the browser set it
    }

    var request = new XMLHttpRequest();
    var loadEvent = 'onreadystatechange';
    var xDomain = false;

    // For IE 8/9 CORS support
    // Only supports POST and GET calls and doesn't returns the response headers.
    // DON'T do this for testing b/c XMLHttpRequest is mocked, not XDomainRequest.
    if (process.env.NODE_ENV !== 'test' &&
        typeof window !== 'undefined' &&
        window.XDomainRequest && !('withCredentials' in request) &&
        !isURLSameOrigin(config.url)) {
      request = new window.XDomainRequest();
      loadEvent = 'onload';
      xDomain = true;
      request.onprogress = function handleProgress() {};
      request.ontimeout = function handleTimeout() {};
    }

    // HTTP basic authentication
    var configAuth = utils.hasOwnProp(config, 'auth') ? config.auth : undefined;
    if (configAuth) {
      // The credential fields are read with an own property check as well:
      // `auth` reaching this point only proves the caller asked for basic
      // authentication, not that they supplied a user name or a password. An
      // `auth` object that leaves either of them out -- `{}` handed over by an
      // interceptor, or a partial `{username: 'me'}` -- resolves the missing
      // field through `Object.prototype`, so a polluted prototype gets to pick
      // the credentials that are sent to the server.
      var username = utils.hasOwnProp(configAuth, 'username') ? configAuth.username || '' : '';
      var password = utils.hasOwnProp(configAuth, 'password') ? configAuth.password || '' : '';
      requestHeaders.Authorization = 'Basic ' + btoa(username + ':' + password);
    }

    var params = utils.hasOwnProp(config, 'params') ? config.params : undefined;
    var paramsSerializer = utils.hasOwnProp(config, 'paramsSerializer') ? config.paramsSerializer : undefined;

    request.open(config.method.toUpperCase(), buildURL(config.url, params, paramsSerializer), true);

    // Set the request timeout in MS
    request.timeout = config.timeout;

    // Listen for ready state
    request[loadEvent] = function handleLoad() {
      if (!request || (request.readyState !== 4 && !xDomain)) {
        return;
      }

      // The request errored out and we didn't get a response, this will be
      // handled by onerror instead
      // With one exception: request that using file: protocol, most browsers
      // will return status as 0 even though it's a successful request
      if (request.status === 0 && !(request.responseURL && request.responseURL.indexOf('file:') === 0)) {
        return;
      }

      // Prepare the response
      var responseHeaders = 'getAllResponseHeaders' in request ? parseHeaders(request.getAllResponseHeaders()) : null;
      var responseData = !config.responseType || config.responseType === 'text' ? request.responseText : request.response;
      var response = {
        data: responseData,
        // IE sends 1223 instead of 204 (https://github.com/mzabriskie/axios/issues/201)
        status: request.status === 1223 ? 204 : request.status,
        statusText: request.status === 1223 ? 'No Content' : request.statusText,
        headers: responseHeaders,
        config: config,
        request: request
      };

      settle(resolve, reject, response);

      // Clean up request
      request = null;
    };

    // Handle low level network errors
    request.onerror = function handleError() {
      // Real errors are hidden from us by the browser
      // onerror should only fire if it's a network error
      reject(createError('Network Error', config, null, request));

      // Clean up request
      request = null;
    };

    // Handle timeout
    request.ontimeout = function handleTimeout() {
      reject(createError('timeout of ' + config.timeout + 'ms exceeded', config, 'ECONNABORTED',
        request));

      // Clean up request
      request = null;
    };

    // Add xsrf header
    // This is only done if running in a standard browser environment.
    // Specifically not if we're in a web worker, or react-native.
    if (utils.isStandardBrowserEnv()) {
      var cookies = require('./../helpers/cookies');

      // The xsrf token is only sent to the same origin, unless the user
      // explicitly opts in for this request via the `withXSRFToken` option.
      if (utils.isFunction(withXSRFToken)) {
        withXSRFToken = withXSRFToken(config);
      }

      // Strict boolean check (GHSA-xx6v-rp6x-q39c): only an explicit `true`
      // short-circuits the same origin guard. A truthy non boolean -- `1`,
      // `'yes'`, `{}` -- reaching the config as an own property (attacker
      // controlled JSON handed to `axios.request`) or returned by the resolver
      // function must never be enough to ship the token to a foreign origin.
      if (withXSRFToken === true || (withXSRFToken !== false && isURLSameOrigin(config.url))) {
        // Add xsrf header
        var xsrfValue = xsrfHeaderName && xsrfCookieName && cookies.read(xsrfCookieName);

        if (xsrfValue) {
          requestHeaders[xsrfHeaderName] = xsrfValue;
        }
      }
    }

    // Add headers to the request
    if ('setRequestHeader' in request) {
      utils.forEach(requestHeaders, function setRequestHeader(val, key) {
        if (typeof requestData === 'undefined' && key.toLowerCase() === 'content-type') {
          // Remove Content-Type if data is undefined
          delete requestHeaders[key];
        } else {
          // Otherwise add header to the request
          request.setRequestHeader(key, val);
        }
      });
    }

    // Add withCredentials to request if needed
    if (utils.hasOwnProp(config, 'withCredentials') && config.withCredentials) {
      request.withCredentials = true;
    }

    // Add responseType to request if needed
    if (config.responseType) {
      try {
        request.responseType = config.responseType;
      } catch (e) {
        // Expected DOMException thrown by browsers not compatible XMLHttpRequest Level 2.
        // But, this can be suppressed for 'json' type as it can be parsed by default 'transformResponse' function.
        if (config.responseType !== 'json') {
          throw e;
        }
      }
    }

    // Handle progress if needed
    // The progress handlers are invoked with the in-flight payload, so only own
    // listeners are attached.
    var onDownloadProgress = utils.hasOwnProp(config, 'onDownloadProgress') ? config.onDownloadProgress : undefined;
    var onUploadProgress = utils.hasOwnProp(config, 'onUploadProgress') ? config.onUploadProgress : undefined;

    if (typeof onDownloadProgress === 'function') {
      request.addEventListener('progress', onDownloadProgress);
    }

    // Not all browsers support upload events
    if (typeof onUploadProgress === 'function' && request.upload) {
      request.upload.addEventListener('progress', onUploadProgress);
    }

    var cancelToken = utils.hasOwnProp(config, 'cancelToken') ? config.cancelToken : undefined;
    if (cancelToken) {
      // Handle cancellation
      cancelToken.promise.then(function onCanceled(cancel) {
        if (!request) {
          return;
        }

        request.abort();
        reject(cancel);
        // Clean up request
        request = null;
      });
    }

    if (requestData === undefined) {
      requestData = null;
    }

    // Send the request
    request.send(requestData);
  });
};
