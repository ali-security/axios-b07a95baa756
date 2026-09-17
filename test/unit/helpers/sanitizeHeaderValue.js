var sanitizeHeaderValue = require('../../../lib/helpers/sanitizeHeaderValue');

module.exports = {
  testRemoveInvalidHeaderCharacters: function (test) {
    test.strictEqual(sanitizeHeaderValue('ok\r\nInjected: yes'), 'okInjected: yes');
    test.strictEqual(sanitizeHeaderValue('ok\x01bad'), 'okbad');
    test.done();
  },

  testRemoveBoundaryWhitespace: function (test) {
    test.strictEqual(sanitizeHeaderValue(' value\t'), 'value');
    test.done();
  },

  testSanitizeArrayValuesRecursively: function (test) {
    test.deepEqual(
      sanitizeHeaderValue([' safe=1 ', 'unsafe=1\nInjected: true']),
      ['safe=1', 'unsafe=1Injected: true']
    );
    test.done();
  },

  testPreserveNullishAndFalseValues: function (test) {
    test.strictEqual(sanitizeHeaderValue(false), false);
    test.strictEqual(sanitizeHeaderValue(null), null);
    test.strictEqual(sanitizeHeaderValue(undefined), undefined);
    test.done();
  }
};
