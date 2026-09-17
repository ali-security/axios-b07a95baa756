var cookies = require('../../lib/helpers/cookies');

describe('xsrf', function () {
  beforeEach(function () {
    jasmine.Ajax.install();
  });

  afterEach(function () {
    document.cookie = axios.defaults.xsrfCookieName + '=;expires=' + new Date(Date.now() - 86400000).toGMTString();
    jasmine.Ajax.uninstall();
  });

  it('should not set xsrf header if cookie is null', function (done) {
    axios('/foo');

    getAjaxRequest().then(function (request) {
      expect(request.requestHeaders[axios.defaults.xsrfHeaderName]).toEqual(undefined);
      done();
    });
  });

  it('should set xsrf header if cookie is set', function (done) {
    document.cookie = axios.defaults.xsrfCookieName + '=12345';

    axios('/foo');

    getAjaxRequest().then(function (request) {
      expect(request.requestHeaders[axios.defaults.xsrfHeaderName]).toEqual('12345');
      done();
    });
  });

  it('should not set xsrf header if xsrfCookieName is null', function (done) {
    document.cookie = axios.defaults.xsrfCookieName + '=12345';

    axios('/foo', {
      xsrfCookieName: null
    });

    getAjaxRequest().then(function (request) {
      expect(request.requestHeaders[axios.defaults.xsrfHeaderName]).toEqual(undefined);
      done();
    });
  });

  it('should not read cookies at all if xsrfCookieName is null', function (done) {
    spyOn(cookies, "read");

    axios('/foo', {
      xsrfCookieName: null
    });

    getAjaxRequest().then(function (request) {
      expect(cookies.read).not.toHaveBeenCalled();
      done();
    });
  });

  it('should not treat regex-like xsrfCookieName as a pattern', function (done) {
    document.cookie = axios.defaults.xsrfCookieName + '=12345';

    axios('/foo', {
      xsrfCookieName: 'XSRF.*'
    });

    getAjaxRequest().then(function (request) {
      expect(request.requestHeaders[axios.defaults.xsrfHeaderName]).toEqual(undefined);
      done();
    });
  });

  it('should not set xsrf header for cross origin', function (done) {
    document.cookie = axios.defaults.xsrfCookieName + '=12345';

    axios('http://example.com/');

    getAjaxRequest().then(function (request) {
      expect(request.requestHeaders[axios.defaults.xsrfHeaderName]).toEqual(undefined);
      done();
    });
  });

  it('should not set xsrf header for cross origin when using withCredentials', function (done) {
    document.cookie = axios.defaults.xsrfCookieName + '=12345';

    axios('http://example.com/', {
      withCredentials: true
    });

    getAjaxRequest().then(function (request) {
      expect(request.requestHeaders[axios.defaults.xsrfHeaderName]).toEqual(undefined);
      done();
    });
  });

  it('should set xsrf header for cross origin when using withCredentials and withXSRFToken', function (done) {
    document.cookie = axios.defaults.xsrfCookieName + '=12345';

    axios('http://example.com/', {
      withCredentials: true,
      withXSRFToken: true
    });

    getAjaxRequest().then(function (request) {
      expect(request.requestHeaders[axios.defaults.xsrfHeaderName]).toEqual('12345');
      done();
    });
  });

  describe('withXSRFToken option', function () {
    it('should set xsrf header for cross origin when withXSRFToken = true', function (done) {
      var token = '12345';

      document.cookie = axios.defaults.xsrfCookieName + '=' + token;

      axios('http://example.com/', {
        withXSRFToken: true
      });

      getAjaxRequest().then(function (request) {
        expect(request.requestHeaders[axios.defaults.xsrfHeaderName]).toEqual(token);
        done();
      });
    });

    it('should not set xsrf header for the same origin when withXSRFToken = false', function (done) {
      var token = '12345';

      document.cookie = axios.defaults.xsrfCookieName + '=' + token;

      axios('/foo', {
        withXSRFToken: false
      });

      getAjaxRequest().then(function (request) {
        expect(request.requestHeaders[axios.defaults.xsrfHeaderName]).toEqual(undefined);
        done();
      });
    });

    it('should support function resolver', function (done) {
      var token = '12345';

      document.cookie = axios.defaults.xsrfCookieName + '=' + token;

      axios('/foo', {
        withXSRFToken: function (config) { return config.userFlag === 'yes'; },
        userFlag: 'yes'
      });

      getAjaxRequest().then(function (request) {
        expect(request.requestHeaders[axios.defaults.xsrfHeaderName]).toEqual(token);
        done();
      });
    });
  });

  // CVE-2026-42042 / GHSA-xx6v-rp6x-q39c.
  //
  // `withXSRFToken` used to be evaluated for truthiness, so any truthy value --
  // `1`, `'yes'`, `{}`, or whatever a resolver function happened to return --
  // short-circuited the same origin guard and shipped the victim's xsrf token
  // to a foreign origin. Only an explicit `true` may do that; every other
  // truthy value has to fall back to the same origin check.
  describe('withXSRFToken strict boolean check', function () {
    var token = '12345';

    function expectNoTokenCrossOrigin(config, done) {
      document.cookie = axios.defaults.xsrfCookieName + '=' + token;

      axios('http://example.com/', config);

      getAjaxRequest().then(function (request) {
        // Unpatched the truthy value bypasses `isURLSameOrigin` and the token
        // is handed to the attacker's host.
        expect(request.requestHeaders[axios.defaults.xsrfHeaderName]).toEqual(undefined);
        done();
      });
    }

    it('should not set xsrf header for cross origin when withXSRFToken is a truthy string', function (done) {
      expectNoTokenCrossOrigin({ withXSRFToken: 'yes' }, done);
    });

    it('should not set xsrf header for cross origin when withXSRFToken is a truthy number', function (done) {
      expectNoTokenCrossOrigin({ withXSRFToken: 1 }, done);
    });

    it('should not set xsrf header for cross origin when withXSRFToken is an object', function (done) {
      expectNoTokenCrossOrigin({ withXSRFToken: {} }, done);
    });

    it('should not set xsrf header for cross origin when withXSRFToken comes from attacker JSON', function (done) {
      // The realistic delivery: a config object parsed from attacker
      // controlled JSON. `withXSRFToken` lands as an *own* property, so the
      // own property guard alone does not stop it.
      expectNoTokenCrossOrigin(JSON.parse('{"withXSRFToken": 1}'), done);
    });

    it('should not set xsrf header for cross origin when the resolver returns a truthy non boolean', function (done) {
      expectNoTokenCrossOrigin({
        withXSRFToken: function () { return 'yes'; }
      }, done);
    });

    it('should still set xsrf header for cross origin when withXSRFToken is exactly true', function (done) {
      document.cookie = axios.defaults.xsrfCookieName + '=' + token;

      axios('http://example.com/', { withXSRFToken: true });

      getAjaxRequest().then(function (request) {
        expect(request.requestHeaders[axios.defaults.xsrfHeaderName]).toEqual(token);
        done();
      });
    });

    it('should still set xsrf header for cross origin when the resolver returns true', function (done) {
      document.cookie = axios.defaults.xsrfCookieName + '=' + token;

      axios('http://example.com/', {
        withXSRFToken: function () { return true; }
      });

      getAjaxRequest().then(function (request) {
        expect(request.requestHeaders[axios.defaults.xsrfHeaderName]).toEqual(token);
        done();
      });
    });

    it('should still set xsrf header for the same origin when withXSRFToken is a truthy non boolean', function (done) {
      // Same origin behaviour is unchanged: the token was always allowed here,
      // and a truthy non boolean must not turn into an opt *out*.
      document.cookie = axios.defaults.xsrfCookieName + '=' + token;

      axios('/foo', { withXSRFToken: 'yes' });

      getAjaxRequest().then(function (request) {
        expect(request.requestHeaders[axios.defaults.xsrfHeaderName]).toEqual(token);
        done();
      });
    });

    it('should still set xsrf header for the same origin when withXSRFToken is omitted', function (done) {
      document.cookie = axios.defaults.xsrfCookieName + '=' + token;

      axios('/foo');

      getAjaxRequest().then(function (request) {
        expect(request.requestHeaders[axios.defaults.xsrfHeaderName]).toEqual(token);
        done();
      });
    });

    it('should still honour an explicit false on the same origin', function (done) {
      document.cookie = axios.defaults.xsrfCookieName + '=' + token;

      axios('/foo', { withXSRFToken: false });

      getAjaxRequest().then(function (request) {
        expect(request.requestHeaders[axios.defaults.xsrfHeaderName]).toEqual(undefined);
        done();
      });
    });
  });
});
