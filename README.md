# Signed-Cookie-Lib
Simple library for creating and validating custom session/token cookies that use a cryptographic signature for verification.

```
# Usage:
$expires = time()+3600;
$path = '/';
$domain = '.example.com';
$key = 'a cryptographically strong key for HMAC hashes.';
$algo = 'sha256';

$name = 'EXAMPLE_SESSION';
$value = 'An unsigned string.';

# Create signed cookie.

$c = new SignedCookieLib($expires, $path, $domain, $key, $algo);

$c->setCookie($name, $value)
```
```
# Cookie validation example.

$c = new SignedCookieLib($expires, $path, $domain, $key, $algo);
$result = $c->isValid($cookieName, $cookieUnsignedValue);
```
You can use this as an alternative method of validating logged in users with a private key or use this as a simple validation method for changing account passwords and other uses where you might like to use secure validation without dependence on a user information database or other data source.
