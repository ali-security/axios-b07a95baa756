'use strict';

var defaults = require('./../defaults');
var utils = require('./../utils');
var InterceptorManager = require('./InterceptorManager');
var dispatchRequest = require('./dispatchRequest');
var buildFullPath = require('./buildFullPath');

/**
 * Create a new instance of Axios
 *
 * @param {Object} instanceConfig The default config for the instance
 */
function Axios(instanceConfig) {
  this.defaults = instanceConfig;
  this.interceptors = {
    request: new InterceptorManager(),
    response: new InterceptorManager()
  };
}

/**
 * Dispatch a request
 *
 * @param {Object} config The config specific for this request (merged with this.defaults)
 */
Axios.prototype.request = function request(config) {
  /*eslint no-param-reassign:0*/
  // Allow for axios('example/url'[, config]) a la fetch API
  if (typeof config === 'string') {
    config = utils.merge({
      url: arguments[0]
    }, arguments[1]);
  }

  config = utils.merge(defaults, this.defaults, { method: 'get' }, config);

  // Set config.allowAbsoluteUrls
  // Only own properties are honoured: a polluted `Object.prototype` must not be
  // able to decide whether an absolute url may bypass the baseURL.
  var ownAllowAbsoluteUrls = utils.hasOwnProp(config, 'allowAbsoluteUrls') ? config.allowAbsoluteUrls : undefined;
  var defaultAllowAbsoluteUrls;
  if (utils.hasOwnProp(this.defaults, 'allowAbsoluteUrls')) {
    defaultAllowAbsoluteUrls = this.defaults.allowAbsoluteUrls;
  }

  if (ownAllowAbsoluteUrls !== undefined) {
    config.allowAbsoluteUrls = ownAllowAbsoluteUrls;
  } else if (defaultAllowAbsoluteUrls !== undefined) {
    config.allowAbsoluteUrls = defaultAllowAbsoluteUrls;
  } else {
    config.allowAbsoluteUrls = true;
  }

  config.method = config.method.toLowerCase();

  // Support baseURL config
  // An inherited `baseURL` would silently retarget every relative request at a
  // host the caller never configured, so only an own value is used.
  var baseURL = utils.hasOwnProp(config, 'baseURL') ? config.baseURL : undefined;
  config.url = buildFullPath(baseURL, config.url, config.allowAbsoluteUrls);

  // Hook up interceptors middleware
  var chain = [dispatchRequest, undefined];
  var promise = Promise.resolve(config);

  this.interceptors.request.forEach(function unshiftRequestInterceptors(interceptor) {
    chain.unshift(interceptor.fulfilled, interceptor.rejected);
  });

  this.interceptors.response.forEach(function pushResponseInterceptors(interceptor) {
    chain.push(interceptor.fulfilled, interceptor.rejected);
  });

  while (chain.length) {
    promise = promise.then(chain.shift(), chain.shift());
  }

  return promise;
};

// Provide aliases for supported request methods
utils.forEach(['delete', 'get', 'head', 'options'], function forEachMethodNoData(method) {
  /*eslint func-names:0*/
  Axios.prototype[method] = function(url, config) {
    return this.request(utils.merge(config || {}, {
      method: method,
      url: url
    }));
  };
});

utils.forEach(['post', 'put', 'patch'], function forEachMethodWithData(method) {
  /*eslint func-names:0*/
  Axios.prototype[method] = function(url, data, config) {
    return this.request(utils.merge(config || {}, {
      method: method,
      url: url,
      data: data
    }));
  };
});

module.exports = Axios;
