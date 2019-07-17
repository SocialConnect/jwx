<?php
/**
 * SocialConnect project
 * @author: Patsura Dmitry https://github.com/ovr <talk@dmtry.me>
 */
declare(strict_types=1);

namespace SocialConnect\JWX;

use DateTime;
use SocialConnect\JWX\Exception\InvalidJWT;
use SocialConnect\JWX\Exception\RuntimeException;
use SocialConnect\JWX\Exception\UnsupportedSignatureAlgoritm;

class JWS
{
    /**
     * Map of supported algorithms
     *
     * @var array
     */
    public static $algorithms = array(
        // HS
        'HS256' => ['hash_hmac', 'SHA256'],
        'HS384' => ['hash_hmac', 'SHA384'],
        'HS512' => ['hash_hmac', 'SHA512'],
        // RS
        'RS256' => ['openssl', 'SHA256'],
        'RS384' => ['openssl', 'SHA384'],
        'RS512' => ['openssl', 'SHA512'],
    );

    public function signature($private_key_or_secret, $algorithm = 'HS256'): string {
        return $this;
    }

    public function verify(string $alg = null) {
        $algConfiguration = isset(self::$algorithms[$this->header['alg']]);
        if (!$algConfiguration) {
            throw new UnsupportedSignatureAlgoritm($alg);
        }

        throw new UnsupportedSignatureAlgoritm($alg);
    }
}
