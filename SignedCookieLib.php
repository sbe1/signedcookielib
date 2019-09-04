<?php
/**
 * Creates and validates secure signed cookies.
 * Cookies are always flagged HttpOnly.
 * Cookies are always flagged Secure.
 *
 * @author Shawn Ewald <shawn.ewald@gmail.com>
 */
class SignedCookieLib {
    private $cookie_domain;
    private $cookie_expires; # time() value (UNIX timestamp)
    private $cookie_path;
    private $cookie_key;
    private $cookie_algo;
    
    /**
     * Create signature and set cookie.
     * 
     * @param string $name
     * @param string $value
     * @throws InvalidArgumentException
     */
    public function setCookie ($name, $value) {
        if (empty($name)) { throw new InvalidArgumentException('Cookie name required.'); }
        if (empty($value)) { throw new InvalidArgumentException('Cookie value required.'); }
        $signed_value = $this->sign($value);
        setcookie($name, $signed_value, $this->cookie_expires, '/', $this->cookie_domain, true, true);
    }

    /**
     * Validates signed cookie.
     * 
     * @param string $cookiename
     * @param string $unsignedvalue
     * @return boolean
     * @throws InvalidArgumentException
     */
    public function isValid ($cookiename, $unsignedvalue) {
        if (empty($cookiename)) { throw new InvalidArgumentException('Cookie name required.'); }
        if (empty($unsignedvalue)) { throw new InvalidArgumentException('Cookie unsigned value required.'); }
        return $this->sign($unsignedvalue) === filter_input(INPUT_COOKIE, $cookiename);
    }
    
    /**
     * Sign cookie value.
     * 
     * @param string $value Cookie value
     * @return type
     */
    private function sign ($value) {
        return hash_hmac($this->cookie_algo, $value, $this->cookie_key, false);
    }

    /**
     * 
     * @param string $domain
     * @param string $expires time() value (UNIX timestamp)
     * @param string $path
     * @param string $key
     * @param string $algo A valid algorithm for the hash_hmac built in function.
     * @throws InvalidArgumentException
     */
    public function __construct ($expires, $path, $domain, $key, $algo) {
        if (empty($expires) || !is_numeric($expires)
                || ($expires > PHP_INT_MAX) || ($expires < PHP_INT_MIN)) {
            throw new InvalidArgumentException('A valid unix timestamp required for cookie expires value.');
        } 
        $this->cookie_expires = $expires;
        $this->cookie_path = empty($path) ? '/' : $path;
        if (empty($domain)) { throw new InvalidArgumentException('Cookie valid domain required.'); }
        $dtmp = ltrim($domain, '.');
        if (filter_var($dtmp, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
            throw new InvalidArgumentException('Cookie valid domain required.');
        } 
        $this->cookie_domain = $domain;
        if (empty($key)) { throw new InvalidArgumentException('Encryption key required.'); }
        $this->cookie_key = $key;
        if (empty($algo)) { throw new InvalidArgumentException('Cookie signing algorithm name required.'); }
        $this->cookie_algo = $algo;
    }
}