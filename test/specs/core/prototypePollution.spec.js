var utils = require('../../../lib/utils');

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

function captureAdapter(onConfig) {
  // A stand-in adapter: it records the fully merged config and resolves
  // without touching the network.
  return function adapter(config) {
    onConfig(config);
    return Promise.resolve({
      data: '',
      status: 200,
      statusText: 'OK',
      headers: {},
      config: config,
      request: {}
    });
  };
}

describe('Prototype Pollution Protection', function() {
  afterEach(function() {
    // Clean up any pollution that might have occurred
    delete Object.prototype.polluted;
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
});
