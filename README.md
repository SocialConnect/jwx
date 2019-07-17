JWX
===

[![Packagist](https://img.shields.io/packagist/v/socialconnect/jwx.svg?style=flat-square)](https://packagist.org/packages/socialconnect/jwx)
[![License](http://img.shields.io/packagist/l/SocialConnect/jwx.svg?style=flat-square)](https://github.com/SocialConnect/jwx/blob/master/LICENSE)

## [Documentation](https://socialconnect.lowl.io/jwx.html) :: [Getting Started](https://socialconnect.lowl.io/jwx.html)

## Encode

```php
<?php

$jwt = new \SocialConnect\JWX\JWT([
    'uid' => 5,
]);

$token = $jwt->encode('TEST', 'HS256');
var_dump($token);
```

## Decode

```php
<?php

$token = \SocialConnect\JWX\JWT::decode($token, ['key' => 'TEST', 'allowed' => ['HS256']]);
var_dump($token);
```

### License

This project is open-sourced software licensed under the MIT License.

See the [LICENSE](LICENSE) file for more information.
