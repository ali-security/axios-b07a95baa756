var utils = require('../../../lib/utils');
var defaults = require('../../../lib/defaults');
var settle = require('../../../lib/core/settle');

// CVE-2026-42033 helpers.
//
// The property only has to be reachable through the prototype chain for the
// exploit to work, so it is installed as non-enumerable: `for...in` loops in
// jasmine, webpack and the browser shims stay undisturbed while a request is in
// flight, and the vulnerable `config.<option>` reads resolve exactly as they
// would for real pollution.
var pollutedKeys = [];

function pollute(key, value) {
  Object.defineProperty(Object.prototype, key, {
    value: value,
    writable: true,
    configurable: true,
    enumerable: false
  });
  pollutedKeys.push(key);
}

// CVE-2026-42041 helper.
//
// The nastier shape of prototype pollution is an accessor pair rather than a
// plain value: the setter swallows the write, so `target[key] = ...` never
// creates an own property on the merge result and every later read keeps
// resolving to the attacker's getter.
function polluteAccessor(key, value) {
  Object.defineProperty(Object.prototype, key, {
    get: function() { return value; },
    set: function() { /* swallow the write */ },
    configurable: true,
    enumerable: false
  });
  pollutedKeys.push(key);
}

function cleanPollution() {
  while (pollutedKeys.length) {
    delete Object.prototype[pollutedKeys.pop()];
  }
}

// CVE-2026-25639 regression suite.
//
// A configuration object built from attacker controlled JSON carries
// `__proto__` (and friends) as *own* properties. axios 0.16.2 has no
// `lib/core/mergeConfig.js` yet -- every config and header object is merged
// through `utils.merge`, whose `assignValue` happily performed
// `result['__proto__'] = ...`. That re-parents the merged config on an
// attacker supplied object, so lookups such as `config.baseURL` resolve to
// attacker data (request retargeting / SSRF) even though the caller never set
// them. The fix filters `__proto__`, `constructor` and `prototype` before any
// assignment happens.

function captureAdapter(onConfig, responseData) {
  // A stand-in adapter: it records the fully merged config and resolves
  // without touching the network.
  return function adapter(config) {
    onConfig(config);
    return Promise.resolve({
      data: typeof responseData === 'undefined' ? '' : responseData,
      status: 200,
      statusText: 'OK',
      headers: {},
      config: config,
      request: {}
    });
  };
}

function settlingAdapter(status, statusText) {
  // A stand-in adapter that hands the response to `settle`, exactly like the
  // real xhr and http adapters do, so `validateStatus` decides the outcome.
  return function adapter(config) {
    return new Promise(function(resolve, reject) {
      settle(resolve, reject, {
        data: '',
        status: status,
        statusText: statusText,
        headers: {},
        config: config,
        request: {}
      });
    });
  };
}

describe('Prototype Pollution Protection', function() {
  afterEach(function() {
    // Clean up any pollution that might have occurred
    delete Object.prototype.polluted;
    cleanPollution();
  });

  describe('utils.merge', function() {
    it('should filter __proto__ key at top level', function() {
      var result = utils.merge(
        {},
        { __proto__: { polluted: 'yes' }, safe: 'value' }
      );

      expect(Object.prototype.polluted).toEqual(undefined);
      expect(result.safe).toEqual('value');
      expect(result.hasOwnProperty('__proto__')).toEqual(false);
      expect(result.polluted).toEqual(undefined);
    });

    it('should filter constructor key at top level', function() {
      var result = utils.merge(
        {},
        { constructor: { polluted: 'yes' }, safe: 'value' }
      );

      expect(result.safe).toEqual('value');
      expect(result.hasOwnProperty('constructor')).toEqual(false);
    });

    it('should filter prototype key at top level', function() {
      var result = utils.merge(
        {},
        { prototype: { polluted: 'yes' }, safe: 'value' }
      );

      expect(result.safe).toEqual('value');
      expect(result.hasOwnProperty('prototype')).toEqual(false);
    });

    it('should filter __proto__ key in nested objects', function() {
      // `merge` in 0.16.2 only recurses when the target already holds an
      // object under that key -- which is exactly what happens for `headers`,
      // since the defaults always provide one. Seed it so the nested branch
      // is the one under test, and use JSON.parse so `__proto__` really is an
      // own property of the payload.
      var result = utils.merge(
        { headers: {} },
        JSON.parse('{"headers": {"__proto__": {"polluted": "nested"}, "Content-Type": "application/json"}}')
      );

      expect(Object.prototype.polluted).toEqual(undefined);
      expect(result.headers['Content-Type']).toEqual('application/json');
      expect(result.headers.polluted).toEqual(undefined);
      expect(result.headers.hasOwnProperty('__proto__')).toEqual(false);
    });

    it('should filter constructor key in nested objects', function() {
      var result = utils.merge(
        { headers: {} },
        {
          headers: {
            constructor: { prototype: { polluted: 'nested' } },
            'Content-Type': 'application/json'
          }
        }
      );

      expect(Object.prototype.polluted).toEqual(undefined);
      expect(result.headers['Content-Type']).toEqual('application/json');
      expect(result.headers.hasOwnProperty('constructor')).toEqual(false);
    });

    it('should filter prototype key in nested objects', function() {
      var result = utils.merge(
        { headers: {} },
        {
          headers: {
            prototype: { polluted: 'nested' },
            'Content-Type': 'application/json'
          }
        }
      );

      expect(result.headers['Content-Type']).toEqual('application/json');
      expect(result.headers.hasOwnProperty('prototype')).toEqual(false);
    });

    it('should filter dangerous keys in deeply nested objects', function() {
      var result = utils.merge(
        { level1: { level2: {} } },
        JSON.parse(
          '{"level1": {"level2": {"__proto__": {"polluted": "deep"}, "prototype": {"polluted": "deep"}, "safe": "value"}}}'
        )
      );

      expect(Object.prototype.polluted).toEqual(undefined);
      expect(result.level1.level2.safe).toEqual('value');
      expect(result.level1.level2.polluted).toEqual(undefined);
      expect(result.level1.level2.hasOwnProperty('__proto__')).toEqual(false);
      expect(result.level1.level2.hasOwnProperty('prototype')).toEqual(false);
    });

    it('should still merge regular properties correctly', function() {
      var result = utils.merge({ a: 1, b: { c: 2 } }, { b: { d: 3 }, e: 4 });

      expect(result.a).toEqual(1);
      expect(result.b.c).toEqual(2);
      expect(result.b.d).toEqual(3);
      expect(result.e).toEqual(4);
    });

    it('should handle JSON.parse payloads safely', function() {
      var malicious = JSON.parse('{"__proto__": {"polluted": "yes"}}');
      var result = utils.merge({}, malicious);

      expect(Object.prototype.polluted).toEqual(undefined);
      expect(result.hasOwnProperty('__proto__')).toEqual(false);
      // Without the guard the merged object is re-parented on the payload and
      // silently inherits every property the attacker put there.
      expect(result.polluted).toEqual(undefined);
    });

    it('should handle nested JSON.parse payloads safely', function() {
      var malicious = JSON.parse(
        '{"headers": {"constructor": {"prototype": {"polluted": "yes"}}}}'
      );
      var result = utils.merge({ headers: {} }, malicious);

      expect(Object.prototype.polluted).toEqual(undefined);
      expect(result.headers.hasOwnProperty('constructor')).toEqual(false);
    });

    it('should not pollute the flattened headers built by dispatchRequest', function() {
      // Mirrors `dispatchRequest`: common headers, per-method headers and the
      // request headers are collapsed with `utils.merge`.
      var result = utils.merge(
        { Accept: 'application/json' },
        {},
        JSON.parse('{"__proto__": {"polluted": "header"}, "Content-Type": "application/json"}')
      );

      expect(Object.prototype.polluted).toEqual(undefined);
      expect(result.Accept).toEqual('application/json');
      expect(result['Content-Type']).toEqual('application/json');
      expect(result.polluted).toEqual(undefined);
    });
  });

  describe('request config merging', function() {
    // 0.16.2 has no `mergeConfig` module: `Axios.prototype.request` merges the
    // per-request config through `utils.merge`, so these exercise the same
    // entry point the advisory's proof of concept uses -- `axios.request()`
    // and the method shortcuts -- with a stub adapter in place of the network.

    it('should filter dangerous keys at top level', function(done) {
      var captured = null;
      var malicious = JSON.parse(
        '{"__proto__": {"polluted": "yes"}, "constructor": {"polluted": "yes"}, "prototype": {"polluted": "yes"}, "url": "/api/test"}'
      );
      malicious.adapter = captureAdapter(function(config) {
        captured = config;
      });

      axios.request(malicious).then(function() {
        expect(Object.prototype.polluted).toEqual(undefined);
        expect(captured.url).toEqual('/api/test');
        expect(captured.polluted).toEqual(undefined);
        expect(captured.hasOwnProperty('__proto__')).toEqual(false);
        expect(captured.hasOwnProperty('constructor')).toEqual(false);
        expect(captured.hasOwnProperty('prototype')).toEqual(false);
        done();
      }, function(err) {
        fail(err);
        done();
      });
    });

    it('should not inherit an attacker supplied baseURL from a JSON config', function(done) {
      var captured = null;
      var malicious = JSON.parse(
        '{"__proto__": {"baseURL": "http://attacker.test/"}, "url": "/api/test"}'
      );
      malicious.adapter = captureAdapter(function(config) {
        captured = config;
      });

      axios.request(malicious).then(function() {
        // Unpatched, `config.baseURL` resolves through the injected prototype
        // and `buildFullPath` retargets the request at the attacker's host.
        expect(captured.baseURL).toEqual(undefined);
        expect(captured.url).toEqual('/api/test');
        done();
      }, function(err) {
        fail(err);
        done();
      });
    });

    it('should filter dangerous keys in headers', function(done) {
      var captured = null;
      var malicious = JSON.parse(
        '{"url": "/api/test", "headers": {"__proto__": {"polluted": "yes"}, "constructor": {"polluted": "yes"}, "Content-Type": "application/json"}}'
      );
      malicious.adapter = captureAdapter(function(config) {
        captured = config;
      });

      axios.request(malicious).then(function() {
        expect(Object.prototype.polluted).toEqual(undefined);
        expect(captured.headers['Content-Type']).toEqual('application/json');
        expect(captured.headers.polluted).toEqual(undefined);
        expect(captured.headers.hasOwnProperty('__proto__')).toEqual(false);
        expect(captured.headers.hasOwnProperty('constructor')).toEqual(false);
        done();
      }, function(err) {
        fail(err);
        done();
      });
    });

    it('should filter dangerous keys in custom config properties', function(done) {
      var captured = null;
      // The instance defaults already hold an object under `customProp`, so
      // the request value is merged into it -- the same deep branch axios
      // takes for `headers`.
      var instance = axios.create({ customProp: {} });
      var malicious = JSON.parse(
        '{"url": "/api/test", "customProp": {"__proto__": {"polluted": "yes"}, "safe": "value"}}'
      );
      malicious.adapter = captureAdapter(function(config) {
        captured = config;
      });

      instance.request(malicious).then(function() {
        expect(Object.prototype.polluted).toEqual(undefined);
        expect(captured.customProp.safe).toEqual('value');
        expect(captured.customProp.polluted).toEqual(undefined);
        expect(captured.customProp.hasOwnProperty('__proto__')).toEqual(false);
        done();
      }, function(err) {
        fail(err);
        done();
      });
    });

    it('should not fail when the config carries an own __proto__ key', function(done) {
      // The advisory's proof of concept: `axios.get(url, JSON.parse('{"__proto__": {"x": 1}}'))`.
      var captured = null;
      var malicious = JSON.parse('{"__proto__": {"x": 1}}');
      malicious.adapter = captureAdapter(function(config) {
        captured = config;
      });

      axios.get('/api/test', malicious).then(function(response) {
        expect(response.status).toEqual(200);
        expect(captured.url).toEqual('/api/test');
        expect(captured.x).toEqual(undefined);
        done();
      }, function(err) {
        fail(err);
        done();
      });
    });

    it('should still merge configs correctly', function(done) {
      var captured = null;
      var instance = axios.create({
        baseURL: 'https://api.example.com',
        timeout: 1000,
        headers: {
          common: {
            Accept: 'application/json'
          }
        }
      });

      instance.request({
        url: '/users',
        timeout: 5000,
        headers: {
          common: {
            'Content-Type': 'application/json'
          }
        },
        adapter: captureAdapter(function(config) {
          captured = config;
        })
      }).then(function() {
        expect(captured.url).toEqual('https://api.example.com/users');
        expect(captured.timeout).toEqual(5000);
        expect(captured.headers.Accept).toEqual('application/json');
        expect(captured.headers['Content-Type']).toEqual('application/json');
        done();
      }, function(err) {
        fail(err);
        done();
      });
    });
  });

  // CVE-2026-42033: options must never be picked up from `Object.prototype`.
  //
  // `utils.merge` builds the config in a fresh `{}` and every consumer then
  // reads its options back with a bare `config.<option>`; both resolve through
  // the prototype chain. A polluted prototype could therefore become the merge
  // target (injecting headers or an extra transform) or supply options the
  // caller never set.
  describe('inherited config options', function() {
    it('should not use an inherited object as the merge target', function() {
      pollute('headers', { 'X-Injected': 'yes' });

      var result = utils.merge({}, { headers: { 'Content-Type': 'application/json' } });

      expect(result.headers['Content-Type']).toEqual('application/json');
      expect(result.headers['X-Injected']).toEqual(undefined);
      expect(result.headers.hasOwnProperty('X-Injected')).toEqual(false);
    });

    it('should not inherit headers from Object.prototype', function(done) {
      var captured = null;
      pollute('headers', { 'X-Injected': 'yes' });

      axios.request({
        url: '/api/test',
        adapter: captureAdapter(function(config) {
          captured = config;
        })
      }).then(function() {
        expect(captured.headers['X-Injected']).toEqual(undefined);
        expect(captured.headers.Accept).toEqual('application/json, text/plain, */*');
        done();
      }, function(err) {
        fail(err);
        done();
      });
    });

    it('should not inherit baseURL from Object.prototype', function(done) {
      var captured = null;
      pollute('baseURL', 'http://attacker.test');

      axios.request({
        url: '/api/test',
        adapter: captureAdapter(function(config) {
          captured = config;
        })
      }).then(function() {
        // Unpatched `buildFullPath` reads the inherited baseURL and the request
        // leaves for the attacker's host.
        expect(captured.url).toEqual('/api/test');
        done();
      }, function(err) {
        fail(err);
        done();
      });
    });

    it('should not inherit transformRequest from Object.prototype', function(done) {
      var captured = null;
      var tampered = false;

      pollute('transformRequest', [
        function passthrough(data) { return data; },
        function hijack() {
          tampered = true;
          return 'hijacked';
        }
      ]);

      axios.post('/api/test', { a: 1 }, {
        adapter: captureAdapter(function(config) {
          captured = config;
        })
      }).then(function() {
        expect(tampered).toEqual(false);
        expect(captured.data).toEqual('{"a":1}');
        done();
      }, function(err) {
        fail(err);
        done();
      });
    });

    it('should not inherit transformResponse from Object.prototype', function(done) {
      var tampered = false;

      pollute('transformResponse', [
        function passthrough(data) { return data; },
        function hijack() {
          tampered = true;
          return 'hijacked';
        }
      ]);

      axios.request({
        url: '/api/test',
        adapter: captureAdapter(function() {}, '{"ok":true}')
      }).then(function(response) {
        expect(tampered).toEqual(false);
        expect(response.data.ok).toEqual(true);
        done();
      }, function(err) {
        fail(err);
        done();
      });
    });
  });

  // CVE-2026-42041: `validateStatus` is the option that decides whether a
  // response counts as an error, so a prototype gadget that supplies it turns
  // every 401, 403 and 5xx into a success -- authentication failures, WAF
  // blocks and rate limits are all silently swallowed.
  //
  // A plain `Object.prototype.validateStatus = ...` is shadowed here because
  // the default validator is copied out of `lib/defaults.js` on every merge.
  // An accessor pair is not: its setter swallows the copy, `merge` leaves no
  // own property behind and `config.validateStatus` resolves to the attacker's
  // getter. Merging with `Object.defineProperty` always lands an own value, so
  // the inherited accessor is never consulted.
  describe('inherited validateStatus', function() {
    it('should always leave an own validateStatus on the merged config', function() {
      var hijacked = function() { return true; };
      polluteAccessor('validateStatus', hijacked);

      var config = utils.merge(defaults, { method: 'get', url: '/api/test' });

      expect(Object.prototype.hasOwnProperty.call(config, 'validateStatus')).toEqual(true);
      expect(config.validateStatus).not.toBe(hijacked);
      expect(config.validateStatus(401)).toEqual(false);
      expect(config.validateStatus(200)).toEqual(true);
    });

    it('should still reject an unauthorized status when validateStatus is polluted', function() {
      var hijacked = function() { return true; };
      polluteAccessor('validateStatus', hijacked);

      var resolve = jasmine.createSpy('resolve');
      var reject = jasmine.createSpy('reject');
      var config = utils.merge(defaults, { method: 'get', url: '/api/test' });

      settle(resolve, reject, { status: 401, config: config, request: {} });

      expect(resolve).not.toHaveBeenCalled();
      expect(reject).toHaveBeenCalled();
    });

    it('should not let an inherited validateStatus suppress an error response', function(done) {
      var hijacked = function() { return true; };
      polluteAccessor('validateStatus', hijacked);

      axios.request({
        url: '/api/test',
        adapter: settlingAdapter(401, 'Unauthorized')
      }).then(function() {
        // Unpatched the hijacked validator reports the 401 as a success and the
        // caller processes the response as if it were authorized.
        fail('the 401 response should not have been reported as a success');
        done();
      }, function(error) {
        expect(error.message).toEqual('Request failed with status code 401');
        expect(error.response.status).toEqual(401);
        done();
      });
    });

    it('should keep honouring an explicit validateStatus while polluted', function(done) {
      polluteAccessor('validateStatus', function() { return false; });

      axios.request({
        url: '/api/test',
        validateStatus: function(status) { return status === 401; },
        adapter: settlingAdapter(401, 'Unauthorized')
      }).then(function(response) {
        expect(response.status).toEqual(401);
        done();
      }, function(error) {
        fail(error);
        done();
      });
    });
  });

  describe('inherited xhr options', function() {
    beforeEach(function() {
      jasmine.Ajax.install();
    });

    afterEach(function() {
      document.cookie = axios.defaults.xsrfCookieName + '=;expires=' + new Date(Date.now() - 86400000).toGMTString();
      jasmine.Ajax.uninstall();
    });

    it('should not inherit withCredentials from Object.prototype', function(done) {
      pollute('withCredentials', true);

      axios('/foo');

      getAjaxRequest().then(function(request) {
        // Unpatched every request is sent with the user's cookies attached.
        expect(request.withCredentials).not.toEqual(true);
        done();
      });
    });

    it('should not leak the xsrf token cross origin via an inherited withXSRFToken', function(done) {
      document.cookie = axios.defaults.xsrfCookieName + '=12345';
      pollute('withXSRFToken', true);

      axios('http://example.com/');

      getAjaxRequest().then(function(request) {
        expect(request.requestHeaders[axios.defaults.xsrfHeaderName]).toEqual(undefined);
        done();
      });
    });

    it('should not inherit auth from Object.prototype', function(done) {
      pollute('auth', { username: 'attacker', password: 'secret' });

      axios('/foo');

      getAjaxRequest().then(function(request) {
        expect(request.requestHeaders.Authorization).toEqual(undefined);
        done();
      });
    });

    it('should not inherit auth credentials from Object.prototype', function(done) {
      // `auth` itself is an own property here, so the guard around it does not
      // help: without an own `username`/`password` both fields resolved
      // through `Object.prototype` and the attacker picked the credentials
      // that went out on the wire.
      pollute('username', 'attacker');
      pollute('password', 'secret');

      axios('/foo', { auth: {} });

      getAjaxRequest().then(function(request) {
        expect(request.requestHeaders.Authorization).not.toEqual('Basic YXR0YWNrZXI6c2VjcmV0');
        expect(request.requestHeaders.Authorization).toEqual('Basic Og==');
        done();
      });
    });

    it('should not inherit an auth password from Object.prototype', function(done) {
      pollute('password', 'secret');

      axios('/foo', { auth: { username: 'foo' } });

      getAjaxRequest().then(function(request) {
        expect(request.requestHeaders.Authorization).not.toEqual('Basic Zm9vOnNlY3JldA==');
        expect(request.requestHeaders.Authorization).toEqual('Basic Zm9vOg==');
        done();
      });
    });

    it('should not inherit paramsSerializer from Object.prototype', function(done) {
      pollute('paramsSerializer', function hijackSerializer() {
        return 'injected=1';
      });

      axios('/foo', { params: { a: 'b' } });

      getAjaxRequest().then(function(request) {
        expect(request.url).toEqual('/foo?a=b');
        done();
      });
    });

    it('should not inherit params from Object.prototype', function(done) {
      pollute('params', { injected: '1' });

      axios('/foo');

      getAjaxRequest().then(function(request) {
        expect(request.url).toEqual('/foo');
        done();
      });
    });
  });
});
