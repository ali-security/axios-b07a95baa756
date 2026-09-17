var shouldBypassProxy = require('../../../lib/helpers/shouldBypassProxy');

var originalNoProxy = process.env.no_proxy;
var originalNOProxy = process.env.NO_PROXY;

function setNoProxy(value) {
  process.env.no_proxy = value;
  process.env.NO_PROXY = value;
}

module.exports = {
  tearDown: function (callback) {
    if (originalNoProxy === undefined) {
      delete process.env.no_proxy;
    } else {
      process.env.no_proxy = originalNoProxy;
    }

    if (originalNOProxy === undefined) {
      delete process.env.NO_PROXY;
    } else {
      process.env.NO_PROXY = originalNOProxy;
    }

    callback();
  },

  testBypassProxyForLocalhostWithTrailingDot: function (test) {
    setNoProxy('localhost,127.0.0.1,::1');
    test.strictEqual(shouldBypassProxy('http://localhost.:8080/'), true);
    test.done();
  },

  testBypassProxyForBracketedIpv6Loopback: function (test) {
    setNoProxy('localhost,127.0.0.1,::1');
    test.strictEqual(shouldBypassProxy('http://[::1]:8080/'), true);
    test.done();
  },

  testSupportBracketedIpv6EntriesInNoProxy: function (test) {
    setNoProxy('[::1]');
    test.strictEqual(shouldBypassProxy('http://[::1]:8080/'), true);
    test.done();
  },

  testMatchWildcardAndExplicitPorts: function (test) {
    setNoProxy('*.example.com,localhost:8080');

    test.strictEqual(shouldBypassProxy('http://api.example.com/'), true);
    test.strictEqual(shouldBypassProxy('http://localhost:8080/'), true);
    test.strictEqual(shouldBypassProxy('http://localhost:8081/'), false);
    test.done();
  },

  testTreatLocalhostAndLoopbackIpAliasesAsEquivalent: function (test) {
    setNoProxy('localhost');

    test.strictEqual(shouldBypassProxy('http://127.0.0.1:8080/'), true);
    test.strictEqual(shouldBypassProxy('http://[::1]:8080/'), true);

    setNoProxy('127.0.0.1');

    test.strictEqual(shouldBypassProxy('http://localhost:8080/'), true);
    test.strictEqual(shouldBypassProxy('http://[::1]:8080/'), true);

    setNoProxy('::1');

    test.strictEqual(shouldBypassProxy('http://localhost:8080/'), true);
    test.strictEqual(shouldBypassProxy('http://127.0.0.1:8080/'), true);
    test.done();
  },

  testKeepLoopbackAliasMatchingPortAware: function (test) {
    setNoProxy('localhost:8080');

    test.strictEqual(shouldBypassProxy('http://127.0.0.1:8080/'), true);
    test.strictEqual(shouldBypassProxy('http://[::1]:8080/'), true);
    test.strictEqual(shouldBypassProxy('http://127.0.0.1:8081/'), false);
    test.done();
  },

  testMatchWholeHostAndNotSuffix: function (test) {
    setNoProxy('example.com');

    test.strictEqual(shouldBypassProxy('http://example.com/'), true);
    test.strictEqual(shouldBypassProxy('http://notexample.com/'), false);
    test.strictEqual(shouldBypassProxy('http://api.example.com/'), false);
    test.done();
  },

  testWildcardBypassesEverything: function (test) {
    setNoProxy('*');

    test.strictEqual(shouldBypassProxy('http://example.com/'), true);
    test.done();
  },

  testNoBypassWhenNoProxyIsEmpty: function (test) {
    setNoProxy('');

    test.strictEqual(shouldBypassProxy('http://localhost:8080/'), false);
    test.done();
  }
};
