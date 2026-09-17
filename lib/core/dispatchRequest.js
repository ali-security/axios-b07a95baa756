'use strict';

var utils = require('./../utils');
var transformData = require('./transformData');
var isCancel = require('../cancel/isCancel');
var defaults = require('../defaults');
var sanitizeHeaderValue = require('../helpers/sanitizeHeaderValue');

/**
 * Throws a `Cancel` if cancellation has been requested.
 */
function throwIfCancellationRequested(config) {
  // An inherited `cancelToken` would have axios invoke a method off a polluted
  // `Object.prototype` on every single request.
  if (utils.hasOwnProp(config, 'cancelToken') && config.cancelToken) {
    config.cancelToken.throwIfRequested();
  }
}

/**
 * Dispatch a request to the server using the configured adapter.
 *
 * @param {object} config The config that is to be used for the request
 * @returns {Promise} The Promise to be fulfilled
 */
module.exports = function dispatchRequest(config) {
  throwIfCancellationRequested(config);

  // Ensure headers exist
  // Only an own `headers` object is kept: an inherited one would let a polluted
  // `Object.prototype` attach headers to every request.
  config.headers = (utils.hasOwnProp(config, 'headers') && config.headers) || {};

  // Transform request data
  // `transformRequest`/`transformResponse` are invoked with the payload, so an
  // inherited value hands request and response data to attacker code.
  config.data = transformData(
    utils.hasOwnProp(config, 'data') ? config.data : undefined,
    config.headers,
    utils.hasOwnProp(config, 'transformRequest') ? config.transformRequest : undefined
  );

  // Flatten headers
  config.headers = utils.merge(
    utils.hasOwnProp(config.headers, 'common') ? config.headers.common || {} : {},
    utils.hasOwnProp(config.headers, config.method) ? config.headers[config.method] || {} : {},
    config.headers
  );

  utils.forEach(
    ['delete', 'get', 'head', 'post', 'put', 'patch', 'common'],
    function cleanHeaderConfig(method) {
      delete config.headers[method];
    }
  );

  utils.forEach(config.headers, function sanitizeHeaderConfigValue(value, header) {
    config.headers[header] = sanitizeHeaderValue(value);
  });

  // The adapter is the transport every request is handed to, so an inherited
  // one would let a polluted `Object.prototype` intercept the whole exchange.
  var adapter = (utils.hasOwnProp(config, 'adapter') && config.adapter) || defaults.adapter;

  return adapter(config).then(function onAdapterResolution(response) {
    throwIfCancellationRequested(config);

    // Transform response data
    response.data = transformData(
      response.data,
      response.headers,
      utils.hasOwnProp(config, 'transformResponse') ? config.transformResponse : undefined
    );

    return response;
  }, function onAdapterRejection(reason) {
    if (!isCancel(reason)) {
      throwIfCancellationRequested(config);

      // Transform response data
      if (reason && reason.response) {
        reason.response.data = transformData(
          reason.response.data,
          reason.response.headers,
          utils.hasOwnProp(config, 'transformResponse') ? config.transformResponse : undefined
        );
      }
    }

    return Promise.reject(reason);
  });
};
