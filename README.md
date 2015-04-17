JWT - Json Web Token Component
==============================

Copied from: https://github.com/firebase/php-jwt

Converted static functions to instance for dependency injection.

Returned payload as an array instead of a class.

```php
    $jwt = new JwtCoder('my_key');

    $payload =
    [
      "message" => "abc",
      "exp"     => time() + 20
    ];

    $encoded = $jwt->encode($payload);
    $decoded = $jwt->decode($encoded);

    $this->assertEquals($decoded['message'], 'abc');
```

composer require cerad/jwt
