<?php

namespace Cerad\Component\Jwt;

/**
 * NOTE: This was copied and conveerted to an instance
 * docs are not updated
 * 
 * JSON Web Token implementation, based on this spec:
 * http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-06
 *
 * PHP version 5
 *
 * @category Authentication
 * @package  Authentication_JWT
 * @author   Neuman Vong <neuman@twilio.com>
 * @author   Anant Narayanan <anant@php.net>
 * @license  http://opensource.org/licenses/BSD-3-Clause 3-clause BSD
 * @link     https://github.com/firebase/php-jwt
 */
class JwtCoder
{
  static $methods = 
  [
    'HS256' => array('hash_hmac', 'SHA256'), // Default
    'HS512' => array('hash_hmac', 'SHA512'),
    'HS384' => array('hash_hmac', 'SHA384'),
    'RS256' => array('openssl',   'SHA256'), // Needs configuring
  ];
  private $key;
  private $verify;
  
  public function __construct($key,$verify = true)
  {
    $this->key    = $key;
    $this->verify = $verify;
  }
  /**
   * Decodes a JWT string into a PHP object.
   *
   * @param string      $jwt       The JWT
   * @param string|Array|null $key The secret key, or map of keys
   * @param bool        $verify    Don't skip verification process
   *
   * @return object      The JWT's payload as a PHP object
   * @throws UnexpectedValueException Provided JWT was invalid
   * @throws DomainException          Algorithm was not provided
   * 
   * @uses jsonDecode
   * @uses urlsafeB64Decode
   */
  public function decode($jwt, $key = null, $verify = null)
  {
    $key    = $key    !== null ? $key    : $this->key;
    $verify = $verify !== null ? $verify : $this->verify;
    
    $tks = explode('.', $jwt);
    if (count($tks) != 3) {
      throw new \UnexpectedValueException('Wrong number of segments');
    }
    list($headb64, $bodyb64, $cryptob64) = $tks;
    if (null === ($header  = $this->jsonDecode($this->urlsafeB64Decode($headb64)))) {
      throw new \UnexpectedValueException('Invalid segment encoding');
    }
    if (null === ($payload = $this->jsonDecode($this->urlsafeB64Decode($bodyb64)))) {
      throw new \UnexpectedValueException('Invalid segment encoding');
    }
    $sig = $this->urlsafeB64Decode($cryptob64);
    
    if (!$verify) return payload;
    
    if (empty($header['alg'])) {
      throw new \DomainException('Empty algorithm');
    }
    if (!$this->verifySignature("$headb64.$bodyb64", $sig, $key, $header['alg'])) {
      throw new \UnexpectedValueException('Signature verification failed');
    }
    // Check token expiry time if defined. (move to verifyPayload
    if (isset($payload['exp']) && time() >= $payload['exp']){
      throw new \UnexpectedValueException('Expired Token');
    }
    return $payload;
  }

  /**
   * Converts and signs a PHP object or array into a JWT string.
   *
   * @param object|array $payload PHP object or array
   * @param string       $key     The secret key
   * @param string       $algo    The signing algorithm. Supported
   *                              algorithms are 'HS256', 'HS384' and 'HS512'
   *
   * @return string      A signed JWT
   * @uses jsonEncode
   * @uses urlsafeB64Encode
   */
  public function encode($payload, $key = null, $algo = 'HS256')
  {
    $key = $key !== null ? $key : $this->key;
    
    $header = array('typ' => 'JWT', 'alg' => $algo);
    
    $segments = array();
    $segments[] = $this->urlsafeB64Encode($this->jsonEncode($header));
    $segments[] = $this->urlsafeB64Encode($this->jsonEncode($payload));
    $signing_input = implode('.', $segments);

    $signature  = $this->sign($signing_input, $key, $algo);
    $segments[] = $this->urlsafeB64Encode($signature);

    return implode('.', $segments);
  }

  /**
   * Sign a string with a given key and algorithm.
   *
   * @param string $msg          The message to sign
   * @param string|resource $key The secret key
   * @param string $method       The signing algorithm. Supported algorithms
   *                               are 'HS256', 'HS384', 'HS512' and 'RS256'
   *
   * @return string          An encrypted message
   * @throws DomainException Unsupported algorithm was specified
   */
  protected function sign($msg, $key, $method = 'HS256')
  {
    if (empty(self::$methods[$method])) {
      throw new \DomainException('Algorithm not supported');
    }
    list($function, $algo) = self::$methods[$method];
    
    switch($function) 
    {
      case 'hash_hmac': return hash_hmac($algo, $msg, $key, true);
        
      case 'openssl':
        $signature = '';
        $success = openssl_sign($msg, $signature, $key, $algo);
        if(!$success) {
          throw new \DomainException("OpenSSL unable to sign data");
        }
        return $signature;
    }
  }

  /**
   * Verify a signature with the mesage, key and method. Not all methods
   * are symmetric, so we must have a separate verify and sign method.
   * @param string $msg the original message
   * @param string $signature
   * @param string|resource $key for HS*, a string key works. for RS*, must be a resource of an openssl public key
   * @param string $method
   * @return bool
   * @throws DomainException Invalid Algorithm or OpenSSL failure
   */
  protected function verifySignature($msg, $signature, $key, $method = 'HS256') 
  {
    if (empty(self::$methods[$method])) {
      throw new \DomainException('Algorithm not supported');
    }
    list($function, $algo) = self::$methods[$method];
    switch($function) {
      case 'openssl':
        $success = openssl_verify($msg, $signature, $key, $algo);
        if(!$success) {
          throw new \DomainException("OpenSSL unable to verify data: " . openssl_error_string());
        }
        return $signature;
        
      case 'hash_hmac':
      default:
        return $signature === hash_hmac($algo, $msg, $key, true);
    }
  }

  /**
   * Decode a JSON string into a PHP array
   *
   * @param string $input JSON string
   *
   * @return object          Object representation of JSON string
   * @throws DomainException Provided string was invalid JSON
   */
  public function jsonDecode($input)
  {
    if (version_compare(PHP_VERSION, '5.4.0', '>=') && !(defined('JSON_C_VERSION') && PHP_INT_SIZE > 4)) {
      /* In PHP >=5.4.0, json_decode() accepts an options parameter, that allows you to specify that large ints (like Steam
       * Transaction IDs) should be treated as strings, rather than the PHP default behaviour of converting them to floats.
       */
      $decoded = json_decode($input, true, 512, JSON_BIGINT_AS_STRING);
    } else {
      /* Not all servers will support that, however, so for older versions we must manually detect large ints in the JSON
       * string and quote them (thus converting them to strings) before decoding, hence the preg_replace() call.
       */
      $max_int_length = strlen((string) PHP_INT_MAX) - 1;
      $json_without_bigints = preg_replace('/:\s*(-?\d{'.$max_int_length.',})/', ': "$1"', $input);
      $decoded = json_decode($json_without_bigints,true);
    }

    if (function_exists('json_last_error') && $errno = json_last_error()) 
    {
      $this->handleJsonError($errno);
    } 
    else if ($decoded === null && $input !== 'null') 
    {
      throw new \DomainException('Null result with non-null input');
    }
    return $decoded;
  }

  /**
   * Encode a PHP object into a JSON string.
   *
   * @param object|array $input A PHP object or array
   *
   * @return string          JSON representation of the PHP object or array
   * @throws DomainException Provided object could not be encoded to valid JSON
   */
  public function jsonEncode($input)
  {
    $json = json_encode($input);
    if (function_exists('json_last_error') && $errno = json_last_error()) 
    {
      $this->handleJsonError($errno);
    } 
    else if ($json === 'null' && $input !== null) 
    {
      throw new \DomainException('Null result with non-null input');
    }
    return $json;
  }

  /**
   * Decode a string with URL-safe Base64.
   *
   * @param string $input A Base64 encoded string
   *
   * @return string A decoded string
   */
  public function urlsafeB64Decode($input)
  {
    $remainder = strlen($input) % 4;
    if ($remainder) {
      $padlen = 4 - $remainder;
      $input .= str_repeat('=', $padlen);
    }
    return base64_decode(strtr($input, '-_', '+/'));
  }

  /**
   * Encode a string with URL-safe Base64.
   *
   * @param string $input The string you want encoded
   *
   * @return string The base64 encode of what you passed in
   */
  public function urlsafeB64Encode($input)
  {
    return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
  }

  /**
   * Helper method to create a JSON error.
   *
   * @param int $errno An error number from json_last_error()
   *
   * @return void
   */
  private function handleJsonError($errno)
  {
    $messages = array(
      JSON_ERROR_DEPTH     => 'Maximum stack depth exceeded',
      JSON_ERROR_CTRL_CHAR => 'Unexpected control character found',
      JSON_ERROR_SYNTAX    => 'Syntax error, malformed JSON'
    );
    throw new \DomainException(
      isset($messages[$errno])
        ? $messages[$errno]
        : 'Unknown JSON error: ' . $errno
      );
  }
}
