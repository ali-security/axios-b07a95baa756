var cookies = require('../../../lib/helpers/cookies');

describe('helpers::cookies', function () {
  afterEach(function () {
    // Remove all the cookies
    var expires = Date.now() - (60 * 60 * 24 * 7);
    document.cookie.split(';').map(function (cookie) {
      return cookie.split('=')[0];
    }).forEach(function (name) {
      document.cookie = name + '=; expires=' + new Date(expires).toGMTString();
    });
  });

  it('should write cookies', function () {
    cookies.write('foo', 'baz');
    expect(document.cookie).toEqual('foo=baz');
  });

  it('should read cookies', function () {
    cookies.write('foo', 'abc');
    cookies.write('bar', 'def');
    expect(cookies.read('foo')).toEqual('abc');
    expect(cookies.read('bar')).toEqual('def');
  });

  it('should read cookies when the separator has no trailing space', function () {
    var descriptor = Object.getOwnPropertyDescriptor(document, 'cookie');

    Object.defineProperty(document, 'cookie', {
      configurable: true,
      get: function () {
        return 'foo=abc;bar=def';
      }
    });

    try {
      expect(cookies.read('foo')).toEqual('abc');
      expect(cookies.read('bar')).toEqual('def');
    } finally {
      if (descriptor) {
        Object.defineProperty(document, 'cookie', descriptor);
      } else {
        delete document.cookie;
      }
    }
  });

  it('should read cookie names containing regex metacharacters literally', function () {
    cookies.write('foo.*', 'abc');
    cookies.write('foo-value', 'def');

    expect(cookies.read('foo.*')).toEqual('abc');
  });

  it('should not treat regex-like cookie names as patterns', function () {
    cookies.write('foo-value', 'def');

    expect(cookies.read('foo.*')).toEqual(null);
  });

  it('should match cookie names exactly when the name contains regex metacharacters', function () {
    // read() used to build a RegExp by interpolating the requested name, so a
    // metacharacter could silently match a different cookie set by the same site.
    cookies.write('XAY', 'wrong');

    expect(cookies.read('X.Y')).toEqual(null);
  });

  it('should not return a partial match for a name that is a prefix of another cookie', function () {
    cookies.write('xsrf-token-extra', 'wrong');

    expect(cookies.read('xsrf-token')).toEqual(null);
  });

  it('should not throw when reading an invalid regex string as a cookie name', function () {
    cookies.write('foo', 'abc');

    expect(function () {
      expect(cookies.read('[')).toEqual(null);
    }).not.toThrow();
  });

  it('should not hang on a cookie name that is a catastrophic backtracking pattern', function () {
    // The old implementation compiled `(^|;\s*)((a+)+b)=([^;]*)` and ran it against a
    // cookie whose name is a long run of "a", which backtracks exponentially (ReDoS).
    var longName = new Array(33).join('a');
    var start;
    var elapsed;

    cookies.write(longName, 'x');

    start = Date.now();
    expect(cookies.read('(a+)+b')).toEqual(null);
    elapsed = Date.now() - start;

    expect(elapsed).toBeLessThan(1000);
  });

  it('should remove cookies', function () {
    cookies.write('foo', 'bar');
    cookies.remove('foo');
    expect(cookies.read('foo')).toEqual(null);
  });

  it('should uri encode values', function () {
    cookies.write('foo', 'bar baz%');
    expect(document.cookie).toEqual('foo=bar%20baz%25');
  });
});
