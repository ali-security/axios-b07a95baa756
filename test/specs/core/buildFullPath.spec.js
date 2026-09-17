var buildFullPath = require('../../../lib/core/buildFullPath');

describe('helpers::buildFullPath', function () {
  it('should combine URLs', function () {
    expect(buildFullPath('https://api.github.com', '/users')).toBe('https://api.github.com/users');
  });

  it('should return the requestedURL when it is absolute', function () {
    expect(buildFullPath('https://api.github.com', 'https://api.example.com/users')).toBe('https://api.example.com/users');
  });

  it('should combine the URLs when the requestedURL is absolute and allowAbsoluteUrls is false', function () {
    expect(buildFullPath('https://api.github.com', 'https://api.example.com/users', false)).toBe('https://api.github.com/https://api.example.com/users');
  });

  it('should not combine the URLs when the requestedURL is absolute, allowAbsoluteUrls is false, and the baseURL is not configured', function () {
    expect(buildFullPath(undefined, 'https://api.example.com/users', false)).toBe('https://api.example.com/users');
  });

  it('should not combine URLs when the baseURL is not configured', function () {
    expect(buildFullPath(undefined, '/users')).toBe('/users');
  });

  it('should combine URLs when the baseURL and requestedURL are relative', function () {
    expect(buildFullPath('/api', '/users')).toBe('/api/users');
  });

  it('should combine the URLs when the requestedURL is protocol-relative and allowAbsoluteUrls is false', function () {
    expect(buildFullPath('https://api.github.com', '//api.example.com/users', false)).toBe('https://api.github.com/api.example.com/users');
  });
});
