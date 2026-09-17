var axios = require('../../../index');
var http = require('http');
var url = require('url');
var zlib = require('zlib');
var fs = require('fs');
var server, proxy;

// Helpers for the prototype pollution regression tests below.
//
// The polluted properties are installed as *non enumerable* data properties on
// purpose: an enumerable property on `Object.prototype` leaks into every
// `for...in` loop node's http stack (and the other suites) runs, which breaks
// unrelated tests instead of exercising the vulnerability under test.
function pollutePrototype(props) {
  Object.keys(props).forEach(function (key) {
    Object.defineProperty(Object.prototype, key, {
      value: props[key],
      writable: true,
      enumerable: false,
      configurable: true
    });
  });
}

function clearPrototypePollution() {
  delete Object.prototype.auth;
  delete Object.prototype.username;
  delete Object.prototype.password;
  delete Object.prototype.host;
  delete Object.prototype.port;
}

module.exports = {
  setUp: function (callback) {
    // Defensive: make sure no pollution leaked in from another test.
    clearPrototypePollution();

    callback();
  },

  tearDown: function (callback) {
    if (server) {
      server.close();
      server = null;
    }
    if (proxy) {
      proxy.close()
      proxy = null;
    }

    delete process.env.http_proxy;
    delete process.env.HTTP_PROXY;
    delete process.env.https_proxy;
    delete process.env.no_proxy;
    delete process.env.NO_PROXY;

    clearPrototypePollution();

    callback();
  },

  testSanitizeRequestHeadersContainingInvalidCharacters: function (test) {
    server = http.createServer(function (req, res) {
      res.setHeader('Content-Type', 'text/plain');
      res.end(req.headers['x-test']);
    }).listen(4444, function () {
      axios.get('http://localhost:4444/', {
        headers: {
          'x-test': ' ok\r\nInjected: yes\t'
        }
      }).then(function (response) {
        test.equal(response.data, 'okInjected: yes', 'header value should be sanitized');
        test.done();
      }).catch(function (error) {
        test.ok(false, 'request should not fail: ' + error.message);
        test.done();
      });
    });
  },

  testPreserveRequestErrorForUnavailableHostWithInvalidCharacters: function (test) {
    axios.get('http://localhost:1/', {
      headers: {
        'x-test': 'ok\r\nInjected: yes'
      }
    }).then(function () {
      test.ok(false, 'request should not succeed');
      test.done();
    }).catch(function (error) {
      test.notEqual(error.message, 'Invalid character in header content ["x-test"]');
      test.done();
    });
  },

  testTimeout: function (test) {
    server = http.createServer(function (req, res) {
      setTimeout(function () {
        res.end();
      }, 1000);
    }).listen(4444, function () {
      var success = false, failure = false;
      var error;

      axios.get('http://localhost:4444/', {
        timeout: 250
      }).then(function (res) {
        success = true;
      }).catch(function (err) {
        error = err;
        failure = true;
      });

      setTimeout(function () {
        test.equal(success, false, 'request should not succeed');
        test.equal(failure, true, 'request should fail');
        test.equal(error.code, 'ECONNABORTED');
        test.equal(error.message, 'timeout of 250ms exceeded');
        test.done();
      }, 300);
    });
  },

  testJSON: function (test) {
    var data = {
      firstName: 'Fred',
      lastName: 'Flintstone',
      emailAddr: 'fred@example.com'
    };

    server = http.createServer(function (req, res) {
      res.setHeader('Content-Type', 'application/json;charset=utf-8');
      res.end(JSON.stringify(data));
    }).listen(4444, function () {
      axios.get('http://localhost:4444/').then(function (res) {
        test.deepEqual(res.data, data);
        test.done();
      });
    });
  },

  testRedirect: function (test) {
    var str = 'test response';

    server = http.createServer(function (req, res) {
      var parsed = url.parse(req.url);

      if (parsed.pathname === '/one') {
        res.setHeader('Location', '/two');
        res.statusCode = 302;
        res.end();
      } else {
        res.end(str);
      }
    }).listen(4444, function () {
      axios.get('http://localhost:4444/one').then(function (res) {
        test.equal(res.data, str);
        test.equal(res.request.path, '/two');
        test.done();
      });
    });
  },

  testNoRedirect: function (test) {
    server = http.createServer(function (req, res) {
      res.setHeader('Location', '/foo');
      res.statusCode = 302;
      res.end();
    }).listen(4444, function () {
      axios.get('http://localhost:4444/', {
        maxRedirects: 0,
        validateStatus: function () {
          return true;
        }
      }).then(function (res) {
        test.equal(res.status, 302);
        test.equal(res.headers['location'], '/foo');
        test.done();
      });
    });
  },

  testMaxRedirects: function (test) {
    var i = 1;
    server = http.createServer(function (req, res) {
      res.setHeader('Location', '/' + i);
      res.statusCode = 302;
      res.end();
      i++;
    }).listen(4444, function () {
      axios.get('http://localhost:4444/', {
        maxRedirects: 3
      }).catch(function (error) {
        test.done();
      });
    });
  },

  testTransparentGunzip: function (test) {
    var data = {
      firstName: 'Fred',
      lastName: 'Flintstone',
      emailAddr: 'fred@example.com'
    };

    zlib.gzip(JSON.stringify(data), function(err, zipped) {

      server = http.createServer(function (req, res) {
        res.setHeader('Content-Type', 'application/json;charset=utf-8');
        res.setHeader('Content-Encoding', 'gzip');
        res.end(zipped);
      }).listen(4444, function () {
        axios.get('http://localhost:4444/').then(function (res) {
          test.deepEqual(res.data, data);
          test.done();
        });
      });

    });
  },

  testGunzipErrorHandling: function (test) {
    server = http.createServer(function (req, res) {
      res.setHeader('Content-Type', 'application/json;charset=utf-8');
      res.setHeader('Content-Encoding', 'gzip');
      res.end('invalid response');
    }).listen(4444, function () {
      axios.get('http://localhost:4444/').catch(function (error) {
        test.done();
      });
    });
  },

  testUTF8: function (test) {
    var str = Array(100000).join('ж');

    server = http.createServer(function (req, res) {
      res.setHeader('Content-Type', 'text/html; charset=UTF-8');
      res.end(str);
    }).listen(4444, function () {
      axios.get('http://localhost:4444/').then(function (res) {
        test.equal(res.data, str);
        test.done();
      });
    });
  },

  testBasicAuth: function (test) {
    server = http.createServer(function (req, res) {
      res.end(req.headers.authorization);
    }).listen(4444, function () {
      var user = 'foo';
      var headers = { Authorization: 'Bearer 1234' };
      axios.get('http://' + user + '@localhost:4444/', { headers: headers }).then(function (res) {
        var base64 = new Buffer(user + ':', 'utf8').toString('base64');
        test.equal(res.data, 'Basic ' + base64);
        test.done();
      });
    });
  },

  testBasicAuthWithHeader: function (test) {
    server = http.createServer(function (req, res) {
      res.end(req.headers.authorization);
    }).listen(4444, function () {
      var auth = { username: 'foo', password: 'bar' };
      var headers = { Authorization: 'Bearer 1234' };
      axios.get('http://localhost:4444/', { auth: auth, headers: headers }).then(function (res) {
        var base64 = new Buffer('foo:bar', 'utf8').toString('base64');
        test.equal(res.data, 'Basic ' + base64);
        test.done();
      });
    });
  },

  testShouldNormalizeNullishBasicAuthCredentials: function (test) {
    server = http.createServer(function (req, res) {
      res.end(req.headers.authorization);
    }).listen(4444, function () {
      var auth = { username: undefined, password: null };
      axios.get('http://localhost:4444/', { auth: auth }).then(function (res) {
        var base64 = new Buffer(':', 'utf8').toString('base64');
        test.equal(res.data, 'Basic ' + base64, 'nullish own credentials should become empty strings');
        test.done();
      }).catch(function (error) {
        test.ok(false, 'request should not fail: ' + error.message);
        test.done();
      });
    });
  },

  testShouldNotUseInheritedBasicAuthCredentials: function (test) {
    // An `auth` object carrying neither an own `username` nor an own
    // `password` -- what an interceptor that rebuilds the config hands over --
    // used to resolve both fields through `Object.prototype`, so a polluted
    // prototype decided which credentials were sent to the server.
    server = http.createServer(function (req, res) {
      res.end(req.headers.authorization || '');
    }).listen(4444, function () {
      pollutePrototype({
        username: 'attacker',
        password: 'secret'
      });

      var polluted = 'Basic ' + new Buffer('attacker:secret', 'utf8').toString('base64');
      var empty = 'Basic ' + new Buffer(':', 'utf8').toString('base64');

      axios.get('http://localhost:4444/', { auth: {} }).then(function (res) {
        test.notEqual(res.data, polluted, 'should not send inherited basic auth credentials');
        test.equal(res.data, empty, 'missing own credentials should be sent as empty strings');
        test.done();
      }).catch(function (error) {
        test.ok(false, 'request should not fail: ' + error.message);
        test.done();
      });
    });
  },

  testShouldNotUseInheritedBasicAuthPassword: function (test) {
    // Only the password is missing here: the caller's own user name has to
    // survive while the inherited password must not be picked up.
    server = http.createServer(function (req, res) {
      res.end(req.headers.authorization || '');
    }).listen(4444, function () {
      pollutePrototype({
        password: 'secret'
      });

      var polluted = 'Basic ' + new Buffer('foo:secret', 'utf8').toString('base64');
      var expected = 'Basic ' + new Buffer('foo:', 'utf8').toString('base64');

      axios.get('http://localhost:4444/', { auth: { username: 'foo' } }).then(function (res) {
        test.notEqual(res.data, polluted, 'should not send an inherited basic auth password');
        test.equal(res.data, expected, 'the own user name should still be sent');
        test.done();
      }).catch(function (error) {
        test.ok(false, 'request should not fail: ' + error.message);
        test.done();
      });
    });
  },

  testMaxContentLength: function(test) {
    var str = Array(100000).join('ж');

    server = http.createServer(function (req, res) {
      res.setHeader('Content-Type', 'text/html; charset=UTF-8');
      res.end(str);
    }).listen(4444, function () {
      var success = false, failure = false, error;

      axios.get('http://localhost:4444/', {
        maxContentLength: 2000
      }).then(function (res) {
        success = true;
      }).catch(function (err) {
        error = err;
        failure = true;
      });

      setTimeout(function () {
        test.equal(success, false, 'request should not succeed');
        test.equal(failure, true, 'request should fail');
        test.equal(error.message, 'maxContentLength size of 2000 exceeded');
        test.done();
      }, 100);
    });
  },

  testStream: function(test) {
    server = http.createServer(function (req, res) {
      req.pipe(res);
    }).listen(4444, function () {
      axios.post('http://localhost:4444/',
        fs.createReadStream(__filename), {
        responseType: 'stream'
      }).then(function (res) {
        var stream = res.data;
        var string = '';
        stream.on('data', function (chunk) {
          string += chunk.toString('utf8');
        });
        stream.on('end', function () {
          test.equal(string, fs.readFileSync(__filename, 'utf8'));
          test.done();
        });
      });
    });
  },

  testBuffer: function(test) {
    var buf = new Buffer(1024); // Unsafe buffer < Buffer.poolSize (8192 bytes)
    buf.fill('x');
    server = http.createServer(function (req, res) {
      test.equal(req.headers['content-length'], buf.length.toString());
      req.pipe(res);
    }).listen(4444, function () {
      axios.post('http://localhost:4444/',
        buf, {
        responseType: 'stream'
      }).then(function (res) {
        var stream = res.data;
        var string = '';
        stream.on('data', function (chunk) {
          string += chunk.toString('utf8');
        });
        stream.on('end', function () {
          test.equal(string, buf.toString());
          test.done();
        });
      });
    });
  },

  testHTTPProxy: function(test) {
    server = http.createServer(function(req, res) {
      res.setHeader('Content-Type', 'text/html; charset=UTF-8');
      res.end('12345');
    }).listen(4444, function() {
      proxy = http.createServer(function(request, response) {
        var parsed = url.parse(request.url);
        var opts = {
          host: parsed.hostname,
          port: parsed.port,
          path: parsed.path
        };

        http.get(opts, function(res) {
          var body = '';
          res.on('data', function(data) {
            body += data;
          });
          res.on('end', function() {
            response.setHeader('Content-Type', 'text/html; charset=UTF-8');
            response.end(body + '6789');
          });
        });

      }).listen(4000, function() {
        axios.get('http://localhost:4444/', {
          proxy: {
            host: 'localhost',
            port: 4000
          }
        }).then(function(res) {
          test.equal(res.data, '123456789', 'should pass through proxy');
          test.done();
        });
      });
    });
  },

  testHTTPProxyEnv: function(test) {
    server = http.createServer(function(req, res) {
      res.setHeader('Content-Type', 'text/html; charset=UTF-8');
      res.end('4567');
    }).listen(4444, function() {
      proxy = http.createServer(function(request, response) {
        var parsed = url.parse(request.url);
        var opts = {
          host: parsed.hostname,
          port: parsed.port,
          path: parsed.path
        };

        http.get(opts, function(res) {
          var body = '';
          res.on('data', function(data) {
            body += data;
          });
          res.on('end', function() {
            response.setHeader('Content-Type', 'text/html; charset=UTF-8');
            response.end(body + '1234');
          });
        });

      }).listen(4000, function() {
        // set the env variable
        process.env.http_proxy = 'http://localhost:4000/';

        axios.get('http://localhost:4444/').then(function(res) {
          test.equal(res.data, '45671234', 'should use proxy set by process.env.http_proxy');
          test.done();
        });
      });
    });
  },

  testHTTPProxyAuth: function(test) {
    server = http.createServer(function(req, res) {
      res.end();
    }).listen(4444, function() {
      proxy = http.createServer(function(request, response) {
        var parsed = url.parse(request.url);
        var opts = {
          host: parsed.hostname,
          port: parsed.port,
          path: parsed.path
        };
        var proxyAuth = request.headers['proxy-authorization'];

        http.get(opts, function(res) {
          var body = '';
          res.on('data', function(data) {
            body += data;
          });
          res.on('end', function() {
            response.setHeader('Content-Type', 'text/html; charset=UTF-8');
            response.end(proxyAuth);
          });
        });

      }).listen(4000, function() {
        axios.get('http://localhost:4444/', {
          proxy: {
            host: 'localhost',
            port: 4000,
            auth: {
              username: 'user',
              password: 'pass'
            }
          }
        }).then(function(res) {
          var base64 = new Buffer('user:pass', 'utf8').toString('base64');
          test.equal(res.data, 'Basic ' + base64, 'should authenticate to the proxy');
          test.done();
        });
      });
    });
  },

  testHTTPProxyAuthFromEnv: function(test) {
    server = http.createServer(function(req, res) {
      res.end();
    }).listen(4444, function() {
      proxy = http.createServer(function(request, response) {
        var parsed = url.parse(request.url);
        var opts = {
          host: parsed.hostname,
          port: parsed.port,
          path: parsed.path
        };
        var proxyAuth = request.headers['proxy-authorization'];

        http.get(opts, function(res) {
          var body = '';
          res.on('data', function(data) {
            body += data;
          });
          res.on('end', function() {
            response.setHeader('Content-Type', 'text/html; charset=UTF-8');
            response.end(proxyAuth);
          });
        });

      }).listen(4000, function() {
        process.env.http_proxy = 'http://user:pass@localhost:4000/';

        axios.get('http://localhost:4444/').then(function(res) {
          var base64 = new Buffer('user:pass', 'utf8').toString('base64');
          test.equal(res.data, 'Basic ' + base64, 'should authenticate to the proxy set by process.env.http_proxy');
          test.done();
        });
      });
    });
  },

  testHTTPProxyAuthWithHeader: function (test) {
    server = http.createServer(function(req, res) {
      res.end();
    }).listen(4444, function() {
      proxy = http.createServer(function(request, response) {
        var parsed = url.parse(request.url);
        var opts = {
          host: parsed.hostname,
          port: parsed.port,
          path: parsed.path
        };
        var proxyAuth = request.headers['proxy-authorization'];

        http.get(opts, function(res) {
          var body = '';
          res.on('data', function(data) {
            body += data;
          });
          res.on('end', function() {
            response.setHeader('Content-Type', 'text/html; charset=UTF-8');
            response.end(proxyAuth);
          });
        });

      }).listen(4000, function() {
        axios.get('http://localhost:4444/', {
          proxy: {
            host: 'localhost',
            port: 4000,
            auth: {
              username: 'user',
              password: 'pass'
            }
          },
          headers: {
            'Proxy-Authorization': 'Basic abc123'
          }
        }).then(function(res) {
          var base64 = new Buffer('user:pass', 'utf8').toString('base64');
          test.equal(res.data, 'Basic ' + base64, 'should authenticate to the proxy');
          test.done();
        });
      });
    });
  },

  // `Proxy-Authorization` only ever belongs to the proxy hop. When no proxy
  // applies -- here because `no_proxy` excludes the target -- a header the
  // caller (or a poisoned config) left on the request must not travel to the
  // origin server, whatever casing it was written with.
  testShouldRemoveProxyAuthorizationWhenProxyIsBypassed: function (test) {
    var proxyRequests = 0;

    server = http.createServer(function (req, res) {
      res.setHeader('Content-Type', 'text/html; charset=UTF-8');
      res.end(req.headers['proxy-authorization'] || '');
    }).listen(4444, function () {
      proxy = http.createServer(function (request, response) {
        proxyRequests += 1;
        response.end('proxied');
      }).listen(4000, function () {
        process.env.http_proxy = 'http://user:pass@localhost:4000/';
        process.env.HTTP_PROXY = 'http://user:pass@localhost:4000/';
        process.env.no_proxy = 'localhost';
        process.env.NO_PROXY = 'localhost';

        axios.get('http://localhost:4444/', {
          headers: {
            'pRoXy-AuThOrIzAtIoN': 'Basic c3RhbGU6Y3JlZHM='
          }
        }).then(function (res) {
          test.equal(proxyRequests, 0, 'should not route the bypassed request through the proxy');
          test.equal(res.data, '', 'should not leak Proxy-Authorization to a directly contacted origin');
          test.done();
        }).catch(function (error) {
          test.ok(false, 'request should not fail: ' + error.message);
          test.done();
        });
      });
    });
  },

  testShouldRemoveProxyAuthorizationWhenNoProxyIsConfigured: function (test) {
    server = http.createServer(function (req, res) {
      res.setHeader('Content-Type', 'text/html; charset=UTF-8');
      res.end(req.headers['proxy-authorization'] || '');
    }).listen(4444, function () {
      axios.get('http://localhost:4444/', {
        headers: {
          'Proxy-Authorization': 'Basic c3RhbGU6Y3JlZHM='
        }
      }).then(function (res) {
        test.equal(res.data, '', 'should not leak Proxy-Authorization when no proxy is configured');
        test.done();
      }).catch(function (error) {
        test.ok(false, 'request should not fail: ' + error.message);
        test.done();
      });
    });
  },

  // A stale case variant must not survive next to the credentials computed
  // from the proxy descriptor -- the proxy must only ever see the configured
  // credentials, whichever casing the caller used for its own header.
  testShouldNotSendStaleProxyAuthorizationAlongsideProxyCredentials: function (test) {
    server = http.createServer(function (req, res) {
      res.end();
    }).listen(4444, function () {
      proxy = http.createServer(function (request, response) {
        var parsed = url.parse(request.url);
        var opts = {
          host: parsed.hostname,
          port: parsed.port,
          path: parsed.path
        };
        var proxyAuth = request.headers['proxy-authorization'];

        http.get(opts, function (res) {
          res.on('data', function () {});
          res.on('end', function () {
            response.setHeader('Content-Type', 'text/html; charset=UTF-8');
            response.end(proxyAuth || '');
          });
        });

      }).listen(4000, function () {
        axios.get('http://localhost:4444/', {
          proxy: {
            host: 'localhost',
            port: 4000,
            auth: {
              username: 'user',
              password: 'pass'
            }
          },
          headers: {
            'pRoXy-AuThOrIzAtIoN': 'Basic c3RhbGU6Y3JlZHM='
          }
        }).then(function (res) {
          var base64 = new Buffer('user:pass', 'utf8').toString('base64');
          test.equal(res.data, 'Basic ' + base64,
            'should authenticate to the proxy with the configured credentials only');
          test.done();
        }).catch(function (error) {
          test.ok(false, 'request should not fail: ' + error.message);
          test.done();
        });
      });
    });
  },

  // GHSA-j5f8-grm9-p9fc / GHSA-p92q-9vqr-4j8v: the `Location` a redirect points
  // at is attacker controlled, so the credentials computed for the proxy must
  // never reach it. Every hop is routed back through the proxy
  // (CVE-2020-28168), so the redirect target is only ever reached through the
  // proxy and never receives a `Proxy-Authorization` of its own.
  testShouldRemoveProxyAuthorizationOnRedirectAwayFromTheProxy: function (test) {
    var proxyRequestAuth = [];
    var leakedProxyAuth = 'the redirect target was never contacted';

    // Stands in for the attacker controlled origin the redirect points at.
    server = http.createServer(function (req, res) {
      leakedProxyAuth = req.headers['proxy-authorization'];
      res.setHeader('Content-Type', 'text/html; charset=UTF-8');
      res.end('final');
    }).listen(4444, function () {
      proxy = http.createServer(function (request, response) {
        proxyRequestAuth.push(request.headers['proxy-authorization']);

        if (proxyRequestAuth.length === 1) {
          response.setHeader('Location', 'http://localhost:4444/final');
          response.statusCode = 302;
          response.end();
          return;
        }

        var parsed = url.parse(request.url);
        var opts = {
          host: parsed.hostname,
          port: parsed.port,
          path: parsed.path
        };

        http.get(opts, function (res) {
          var body = '';
          res.on('data', function (data) {
            body += data;
          });
          res.on('end', function () {
            response.setHeader('Content-Type', 'text/html; charset=UTF-8');
            response.end(body);
          });
        });
      }).listen(4000, function () {
        axios.get('http://example.test/start', {
          proxy: {
            host: 'localhost',
            port: 4000,
            auth: {
              username: 'user',
              password: 'pass'
            }
          },
          maxRedirects: 1
        }).then(function (res) {
          var base64 = new Buffer('user:pass', 'utf8').toString('base64');
          test.equal(res.data, 'final', 'should follow the redirect');
          test.deepEqual(proxyRequestAuth, ['Basic ' + base64, 'Basic ' + base64],
            'should authenticate to the proxy itself on every hop');
          test.strictEqual(leakedProxyAuth, undefined,
            'should not leak proxy credentials to the redirect target');
          test.done();
        }).catch(function (error) {
          test.ok(false, 'request should not fail: ' + error.message);
          test.done();
        });
      });
    });
  },

  // `no_proxy` is re-evaluated for the redirect target, so this hop really is
  // sent to the origin directly -- which is exactly when the credentials taken
  // from `http_proxy` have to be dropped from the header bag.
  testShouldRemoveProxyAuthorizationOnRedirectFromTheProxyEnvironmentVariable: function (test) {
    var leakedProxyAuth = 'the redirect target was never contacted';
    var proxyRequests = 0;

    server = http.createServer(function (req, res) {
      leakedProxyAuth = req.headers['proxy-authorization'];
      res.setHeader('Content-Type', 'text/html; charset=UTF-8');
      res.end('final');
    }).listen(4444, function () {
      proxy = http.createServer(function (request, response) {
        proxyRequests += 1;
        response.setHeader('Location', 'http://localhost:4444/final');
        response.statusCode = 302;
        response.end();
      }).listen(4000, function () {
        process.env.http_proxy = 'http://user:pass@localhost:4000/';
        process.env.HTTP_PROXY = 'http://user:pass@localhost:4000/';
        process.env.no_proxy = 'localhost';
        process.env.NO_PROXY = 'localhost';

        axios.get('http://example.test/start', {
          maxRedirects: 1
        }).then(function (res) {
          test.equal(res.data, 'final', 'should follow the redirect');
          test.equal(proxyRequests, 1, 'should only use the proxy for the hop it covers');
          test.strictEqual(leakedProxyAuth, undefined,
            'should not leak credentials taken from http_proxy to the redirect target');
          test.done();
        }).catch(function (error) {
          test.ok(false, 'request should not fail: ' + error.message);
          test.done();
        });
      });
    });
  },

  // Non regression: a `Proxy-Authorization` header is still the supported way
  // to authenticate against an explicitly configured proxy that carries no
  // `auth` descriptor of its own.
  testShouldKeepProxyAuthorizationHeaderWhenProxyHasNoAuth: function (test) {
    server = http.createServer(function (req, res) {
      res.end();
    }).listen(4444, function () {
      proxy = http.createServer(function (request, response) {
        var parsed = url.parse(request.url);
        var opts = {
          host: parsed.hostname,
          port: parsed.port,
          path: parsed.path
        };
        var proxyAuth = request.headers['proxy-authorization'];

        http.get(opts, function (res) {
          res.on('data', function () {});
          res.on('end', function () {
            response.setHeader('Content-Type', 'text/html; charset=UTF-8');
            response.end(proxyAuth || '');
          });
        });

      }).listen(4000, function () {
        axios.get('http://localhost:4444/', {
          proxy: {
            host: 'localhost',
            port: 4000
          },
          headers: {
            'Proxy-Authorization': 'Basic abc123'
          }
        }).then(function (res) {
          test.equal(res.data, 'Basic abc123', 'should send the configured proxy authorization header to the proxy');
          test.done();
        }).catch(function (error) {
          test.ok(false, 'request should not fail: ' + error.message);
          test.done();
        });
      });
    });
  },

  testShouldNotUseInheritedProxyAuthCredentials: function (test) {
    server = http.createServer(function (req, res) {
      res.end();
    }).listen(4444, function () {
      proxy = http.createServer(function (request, response) {
        var parsed = url.parse(request.url);
        var opts = {
          host: parsed.hostname,
          port: parsed.port,
          path: parsed.path,
          // Shadow the polluted `Object.prototype.auth` so node's own http
          // client does not try to build a Basic header out of it.
          auth: undefined
        };
        var proxyAuth = request.headers['proxy-authorization'];

        http.get(opts, function (res) {
          res.on('data', function () {});
          res.on('end', function () {
            response.setHeader('Content-Type', 'text/html; charset=UTF-8');
            response.end(proxyAuth || '');
          });
        });

      }).listen(4000, function () {
        pollutePrototype({
          auth: {},
          username: 'polluted-user',
          password: 'polluted-pass'
        });

        axios.get('http://localhost:4444/', {
          proxy: {
            host: 'localhost',
            port: 4000
          }
        }).then(function (res) {
          test.equal(res.data, '', 'should not send proxy credentials inherited from Object.prototype');
          test.done();
        }).catch(function (error) {
          test.ok(false, 'request should not fail: ' + error.message);
          test.done();
        });
      });
    });
  },

  testShouldNotUseInheritedProxyAuthCredentialsFromEnv: function (test) {
    server = http.createServer(function (req, res) {
      res.end();
    }).listen(4444, function () {
      proxy = http.createServer(function (request, response) {
        var parsed = url.parse(request.url);
        var opts = {
          host: parsed.hostname,
          port: parsed.port,
          path: parsed.path,
          auth: undefined
        };
        var proxyAuth = request.headers['proxy-authorization'];

        http.get(opts, function (res) {
          res.on('data', function () {});
          res.on('end', function () {
            response.setHeader('Content-Type', 'text/html; charset=UTF-8');
            response.end(proxyAuth || '');
          });
        });

      }).listen(4000, function () {
        process.env.http_proxy = 'http://localhost:4000/';

        pollutePrototype({
          auth: {},
          username: 'polluted-user',
          password: 'polluted-pass'
        });

        axios.get('http://localhost:4444/').then(function (res) {
          test.equal(res.data, '', 'should not send proxy credentials inherited from Object.prototype');
          test.done();
        }).catch(function (error) {
          test.ok(false, 'request should not fail: ' + error.message);
          test.done();
        });
      });
    });
  },

  testShouldNotUseInheritedProxyAuthPassword: function (test) {
    server = http.createServer(function (req, res) {
      res.end();
    }).listen(4444, function () {
      proxy = http.createServer(function (request, response) {
        var parsed = url.parse(request.url);
        var opts = {
          host: parsed.hostname,
          port: parsed.port,
          path: parsed.path,
          auth: undefined
        };
        var proxyAuth = request.headers['proxy-authorization'];

        http.get(opts, function (res) {
          res.on('data', function () {});
          res.on('end', function () {
            response.setHeader('Content-Type', 'text/html; charset=UTF-8');
            response.end(proxyAuth || '');
          });
        });

      }).listen(4000, function () {
        pollutePrototype({
          username: 'polluted-user',
          password: 'polluted-pass'
        });

        axios.get('http://localhost:4444/', {
          proxy: {
            host: 'localhost',
            port: 4000,
            auth: {
              username: 'user'
            }
          }
        }).then(function (res) {
          var base64 = new Buffer('user:', 'utf8').toString('base64');
          test.equal(res.data, 'Basic ' + base64, 'should not fall back to an inherited proxy password');
          test.done();
        }).catch(function (error) {
          test.ok(false, 'request should not fail: ' + error.message);
          test.done();
        });
      });
    });
  },

  testShouldNotUseInheritedProxyHostAndPort: function (test) {
    var proxyRequests = 0;

    proxy = http.createServer(function (request, response) {
      proxyRequests += 1;
      response.end('proxied');
    }).listen(4000, function () {
      pollutePrototype({
        host: 'localhost',
        port: 4000
      });

      axios.get('http://localhost:1/', {
        proxy: {},
        timeout: 250
      }).then(function () {
        test.equal(proxyRequests, 0, 'should not route the request through an inherited proxy host');
        test.done();
      }).catch(function () {
        test.equal(proxyRequests, 0, 'should not route the request through an inherited proxy host');
        test.done();
      });
    });
  },

  testNoProxyForLocalhostWithTrailingDot: function (test) {
    var proxyRequests = 0;

    proxy = http.createServer(function (request, response) {
      proxyRequests += 1;
      response.end('proxied');
    }).listen(4000, function () {
      process.env.http_proxy = 'http://localhost:4000/';
      process.env.HTTP_PROXY = 'http://localhost:4000/';
      process.env.no_proxy = 'localhost,127.0.0.1,::1';
      process.env.NO_PROXY = 'localhost,127.0.0.1,::1';

      axios.get('http://localhost.:1/', {
        timeout: 100
      }).then(function () {
        test.ok(false, 'request should not succeed');
        test.equal(proxyRequests, 0, 'should not use proxy for localhost with trailing dot');
        test.done();
      }).catch(function () {
        test.equal(proxyRequests, 0, 'should not use proxy for localhost with trailing dot');
        test.done();
      });
    });
  },

  testNoProxyForBracketedIPv6Loopback: function (test) {
    var proxyRequests = 0;

    proxy = http.createServer(function (request, response) {
      proxyRequests += 1;
      response.end('proxied');
    }).listen(4000, function () {
      process.env.http_proxy = 'http://localhost:4000/';
      process.env.HTTP_PROXY = 'http://localhost:4000/';
      process.env.no_proxy = 'localhost,127.0.0.1,::1';
      process.env.NO_PROXY = 'localhost,127.0.0.1,::1';

      axios.get('http://[::1]:1/', {
        timeout: 100
      }).then(function () {
        test.ok(false, 'request should not succeed');
        test.equal(proxyRequests, 0, 'should not use proxy for IPv6 loopback');
        test.done();
      }).catch(function () {
        test.equal(proxyRequests, 0, 'should not use proxy for IPv6 loopback');
        test.done();
      });
    });
  },

  testNoProxyForIPv4LoopbackAlias: function (test) {
    var proxyRequests = 0;

    proxy = http.createServer(function (request, response) {
      proxyRequests += 1;
      response.end('proxied');
    }).listen(4000, function () {
      process.env.http_proxy = 'http://localhost:4000/';
      process.env.HTTP_PROXY = 'http://localhost:4000/';
      process.env.no_proxy = 'localhost';
      process.env.NO_PROXY = 'localhost';

      axios.get('http://127.0.0.1:1/', {
        timeout: 100
      }).then(function () {
        test.ok(false, 'request should not succeed');
        test.equal(proxyRequests, 0, 'should not use proxy for IPv4 loopback alias');
        test.done();
      }).catch(function () {
        test.equal(proxyRequests, 0, 'should not use proxy for IPv4 loopback alias');
        test.done();
      });
    });
  },

  testNoProxyForIPv6LoopbackAlias: function (test) {
    var proxyRequests = 0;

    proxy = http.createServer(function (request, response) {
      proxyRequests += 1;
      response.end('proxied');
    }).listen(4000, function () {
      process.env.http_proxy = 'http://localhost:4000/';
      process.env.HTTP_PROXY = 'http://localhost:4000/';
      process.env.no_proxy = 'localhost';
      process.env.NO_PROXY = 'localhost';

      axios.get('http://[::1]:1/', {
        timeout: 100
      }).then(function () {
        test.ok(false, 'request should not succeed');
        test.equal(proxyRequests, 0, 'should not use proxy for IPv6 loopback alias');
        test.done();
      }).catch(function () {
        test.equal(proxyRequests, 0, 'should not use proxy for IPv6 loopback alias');
        test.done();
      });
    });
  },

  testNoProxyForUnspecifiedIPv4Address: function (test) {
    // `0.0.0.0` is only a listening wildcard: an outbound request aimed at it
    // reaches the local host, exactly like `localhost` would. It used to fall
    // outside the loopback alias set, so the usual `no_proxy` listing did not
    // cover it and the request -- along with anything it carried -- went
    // through the proxy after all.
    var proxyRequests = 0;

    proxy = http.createServer(function (request, response) {
      proxyRequests += 1;
      response.end('proxied');
    }).listen(4000, function () {
      process.env.http_proxy = 'http://localhost:4000/';
      process.env.HTTP_PROXY = 'http://localhost:4000/';
      process.env.no_proxy = 'localhost,127.0.0.1,::1';
      process.env.NO_PROXY = 'localhost,127.0.0.1,::1';

      axios.get('http://0.0.0.0:1/', {
        timeout: 100
      }).then(function () {
        test.ok(false, 'request should not succeed');
        test.equal(proxyRequests, 0, 'should not use proxy for the unspecified IPv4 address');
        test.done();
      }).catch(function () {
        test.equal(proxyRequests, 0, 'should not use proxy for the unspecified IPv4 address');
        test.done();
      });
    });
  },

  testNoProxyForUnspecifiedIPv6Address: function (test) {
    var proxyRequests = 0;

    proxy = http.createServer(function (request, response) {
      proxyRequests += 1;
      response.end('proxied');
    }).listen(4000, function () {
      process.env.http_proxy = 'http://localhost:4000/';
      process.env.HTTP_PROXY = 'http://localhost:4000/';
      process.env.no_proxy = 'localhost,127.0.0.1,::1';
      process.env.NO_PROXY = 'localhost,127.0.0.1,::1';

      axios.get('http://[::]:1/', {
        timeout: 100
      }).then(function () {
        test.ok(false, 'request should not succeed');
        test.equal(proxyRequests, 0, 'should not use proxy for the unspecified IPv6 address');
        test.done();
      }).catch(function () {
        test.equal(proxyRequests, 0, 'should not use proxy for the unspecified IPv6 address');
        test.done();
      });
    });
  },

  testProxyForDomainsNotInNoProxy: function (test) {
    server = http.createServer(function (req, res) {
      res.setHeader('Content-Type', 'text/html; charset=UTF-8');
      res.end('4567');
    }).listen(4444, function () {
      proxy = http.createServer(function (request, response) {
        var parsed = url.parse(request.url);
        var opts = {
          host: parsed.hostname,
          port: parsed.port,
          path: parsed.path
        };

        http.get(opts, function (res) {
          var body = '';
          res.on('data', function (data) {
            body += data;
          });
          res.on('end', function () {
            response.setHeader('Content-Type', 'text/html; charset=UTF-8');
            response.end(body + '1234');
          });
        });
      }).listen(4000, function () {
        process.env.http_proxy = 'http://localhost:4000/';
        process.env.no_proxy = 'example.com,example.org';

        axios.get('http://localhost:4444/').then(function (res) {
          test.equal(res.data, '45671234', 'should use proxy for domains not in no_proxy');
          test.done();
        }).catch(function (error) {
          test.ok(false, 'request should not fail: ' + error.message);
          test.done();
        });
      });
    });
  },

  testCancel: function(test) {
    var source = axios.CancelToken.source();
    server = http.createServer(function (req, res) {
      // call cancel() when the request has been sent, but a response has not been received
      source.cancel('Operation has been canceled.');
    }).listen(4444, function() {
      axios.get('http://localhost:4444/', {
        cancelToken: source.token
      }).catch(function (thrown) {
        test.ok(thrown instanceof axios.Cancel, 'Promise must be rejected with a Cancel obejct');
        test.equal(thrown.message, 'Operation has been canceled.');
        test.done();
      });
    });
  }
};
