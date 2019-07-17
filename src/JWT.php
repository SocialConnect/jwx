<?php
/**
 * SocialConnect project
 * @author: Patsura Dmitry https://github.com/ovr <talk@dmtry.me>
 */
declare(strict_types=1);

namespace SocialConnect\JWX;

use DateTime;
use SocialConnect\JWX\Exception\ExpiredJWT;
use SocialConnect\JWX\Exception\InvalidJWT;
use SocialConnect\JWX\Exception\RuntimeException;
use SocialConnect\JWX\Exception\UnsupportedSignatureAlgoritm;

class JWT
{
    /**
     * When checking nbf, iat or exp
     * we provide additional time screw/leeway
     *
     * @link https://github.com/SocialConnect/auth/issues/26
     */
    public static $screw = 0;

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
        // ES
        'ES256' => ['openssl', 'SHA256'],
        'ES384' => ['openssl', 'SHA384'],
        'ES512' => ['openssl', 'SHA512'],
    );

    /**
     * @var array
     */
    protected $header;

    /**
     * @var array
     */
    protected $payload;

    /**
     * @var string|null
     */
    protected $signature;

    /**
     * @param string $input Anything really
     *
     * @return string The base64 encode of what you passed in
     */
    public static function urlsafeB64Encode($input)
    {
        return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
    }

    /**
     * @param string $input
     * @return string
     */
    public static function urlsafeB64Decode($input)
    {
        $remainder = strlen($input) % 4;

        if ($remainder) {
            $padlen = 4 - $remainder;
            $input .= str_repeat('=', $padlen);
        }

        return base64_decode(strtr($input, '-_', '+/'));
    }

    /**
     * @param array $payload
     * @param array $header
     * @param string|null $signature
     */
    public function __construct(array $payload, array $header = [], $signature = null)
    {
        $this->payload = $payload;
        $this->header = $header;
        $this->signature = $signature;
    }

    /**
     * @param string $token
     * @param DecodeOptions $options
     * @return JWT
     * @throws InvalidJWT
     */
    public static function decode(string $token, DecodeOptions $options)
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            throw new InvalidJWT('Wrong number of segments');
        }

        list ($header64, $payload64, $signature64) = $parts;

        $headerPayload = base64_decode($header64);
        if (!$headerPayload) {
            throw new InvalidJWT('Cannot decode base64 from header');
        }

        $header = json_decode($headerPayload, true);
        if ($header === null) {
            throw new InvalidJWT('Cannot decode JSON from header');
        }

        $decodedPayload = base64_decode($payload64);
        if (!$decodedPayload) {
            throw new InvalidJWT('Cannot decode base64 from payload');
        }

        $payload = json_decode($decodedPayload, true);
        if ($payload === null) {
            throw new InvalidJWT('Cannot decode JSON from payload');
        }

        $token = new self($payload, $header, self::urlsafeB64Decode($signature64));
        $token->validate("{$header64}.{$payload64}", $options);

        return $token;
    }

    protected function validateHeader(DecodeOptions $options)
    {
        if (!isset($this->header['alg'])) {
            throw new InvalidJWT('No alg inside header');
        }

        if (!$options->isAllowedAlgorithms($this->header['alg'])) {
            throw new InvalidJWT('Not allowed alg inside header');
        }

        if (isset($this->header['kid'])) {
            if (!$options->hasJwkSet()) {
                throw new RuntimeException('Please specify jwk set in DecodeOptions, because there is kid inside header');
            }
        } else {
            if ($options->hasJwkSet()) {
                throw new InvalidJWT('No kid inside header');
            }
        }
    }

    protected function validateClaims()
    {
        $now = time();

        /**
         * @link https://tools.ietf.org/html/rfc7519#section-4.1.5
         * "nbf" (Not Before) Claim check
         */
        if (isset($this->payload['nbf'])) {
            if (!is_numeric($this->payload['nbf'])) {
                throw new InvalidJWT(
                    'nbf (Not Fefore) must be numeric'
                );
            }

            if ($this->payload['nbf'] > ($now + self::$screw)) {
                throw new InvalidJWT(
                    'nbf (Not Fefore) claim is not valid ' . date(DateTime::RFC3339, $this->payload['nbf'])
                );
            }
        }

        /**
         * @link https://tools.ietf.org/html/rfc7519#section-4.1.6
         * "iat" (Issued At) Claim
         */
        if (isset($this->payload['iat'])) {
            if (!is_numeric($this->payload['iat'])) {
                throw new InvalidJWT(
                    'iat (Issued At) must be numeric'
                );
            }

            if ($this->payload['iat'] > ($now + self::$screw)) {
                throw new InvalidJWT(
                    'iat (Issued At) claim is not valid ' . date(DateTime::RFC3339, $this->payload['iat'])
                );
            }
        }

        /**
         * @link https://tools.ietf.org/html/rfc7519#section-4.1.4
         * "exp" (Expiration Time) Claim
         */
        if (isset($this->payload['exp'])) {
            if (!is_numeric($this->payload['exp'])) {
                throw new InvalidJWT(
                    'exp (Expiration Time) must be numeric'
                );
            }

            if (($now - self::$screw) >= $this->payload['exp']) {
                throw new ExpiredJWT(
                    'exp (Expiration Time) claim is not valid ' . date(DateTime::RFC3339, $this->payload['exp'])
                );
            }
        }
    }

    /**
     * @param string $data
     * @param DecodeOptions $options
     * @throws InvalidJWT
     */
    protected function validate($data, DecodeOptions $options)
    {
        $this->validateHeader($options);
        $this->validateClaims();

        $result = $this->verifySignature($data, $options);
        if (!$result) {
            throw new InvalidJWT('Unexpected signature');
        }
    }

    /**
     * @param array $keys
     * @param string $kid
     * @return JWK
     */
    protected function findKeyByKind(array $keys, $kid)
    {
        foreach ($keys as $key) {
            if ($key['kid'] === $kid) {
                return new JWK($key);
            }
        }

        throw new RuntimeException('Unknown key');
    }

    /**
     * @param string $data
     * @param DecodeOptions $options
     * @return bool
     * @throws UnsupportedSignatureAlgoritm
     */
    protected function verifySignature($data, DecodeOptions $options)
    {
        $supported = isset(self::$algorithms[$this->header['alg']]);
        if (!$supported) {
            throw new UnsupportedSignatureAlgoritm($this->header['alg']);
        }

        if ($options->hasJwkSet()) {
            $jwk = $this->findKeyByKind($options->getJwkSet(), $this->header['kid']);
            $secretOrKey = $jwk->getPublicKey();
        } else {
            $secretOrKey = $options->getSecretOrKey();
            if (!$secretOrKey) {
                throw new RuntimeException('Please specify $secretOrKey inside $options');
            }
        }

        list ($function, $signatureAlg) = self::$algorithms[$this->header['alg']];
        switch ($function) {
            case 'openssl':
                if (!function_exists('openssl_verify')) {
                    throw new RuntimeException('Openssl-ext is required to use RS encryption.');
                }

                $result = openssl_verify(
                    $data,
                    $this->signature,
                    $secretOrKey,
                    $signatureAlg
                );
                
                return $result == 1;
            case 'hash_hmac':
                if (!function_exists('hash_hmac')) {
                    throw new RuntimeException('hash-ext is required to use HS encryption.');
                }

                $hash = hash_hmac($signatureAlg, $data, $secretOrKey, true);

                return hash_equals($this->signature, $hash);
        }

        throw new UnsupportedSignatureAlgoritm($this->header['alg']);
    }

    /**
     * @return array
     */
    public function getPayload(): array
    {
        return $this->payload;
    }

    protected function signature(string $privateKeyOrSecret, string $alg, string $data): string
    {
        $supported = isset(self::$algorithms[$alg]);
        if (!$supported) {
            throw new UnsupportedSignatureAlgoritm($alg);
        }

        list ($function, $signatureAlg) = self::$algorithms[$alg];
        switch ($function) {
            case 'openssl':
                if (!function_exists('openssl_verify')) {
                    throw new RuntimeException('Openssl-ext is required to use RS encryption.');
                }

                return openssl_encrypt(
                    $data,
                    $signatureAlg,
                    $privateKeyOrSecret
                );
            case 'hash_hmac':
                if (!function_exists('hash_hmac')) {
                    throw new RuntimeException('hash-ext is required to use HS encryption.');
                }

                return hash_hmac($signatureAlg, $data, $privateKeyOrSecret, true);
        }

        throw new UnsupportedSignatureAlgoritm($this->header['alg']);

    }

    /**
     * @param string $privateKeyOrSecret
     * @param string $alg
     * @param EncodeOptions $options
     * @return string
     */
    public function encode(string $privateKeyOrSecret, string $alg, EncodeOptions $options): string
    {
        $header = $this->header;
        $header['alg'] = $alg;
        $header['typ'] = 'JWT';

        $headerStr = json_encode($header);
        if ($headerStr === false) {
            throw new InvalidJWT('Cannot encode header to JSON');
        }

        $payload = $this->payload;

        if ($options->hasExpirationTime()) {
            $payload['exp'] = time() + $options->getExpirationTime();
        }

        $payloadStr = json_encode($payload);
        if ($payloadStr === false) {
            throw new InvalidJWT('Cannot encode payload to JSON');
        }

        $header64 = base64_encode($headerStr);
        $payload64 = base64_encode($payloadStr);

        $signature = $this->signature($privateKeyOrSecret, $alg, "{$header64}.{$payload64}");
        $signature64 = JWT::urlsafeB64Encode($signature);

        return "{$header64}.{$payload64}.{$signature64}";
    }

    /**
     * @return array
     */
    public function getHeader(): array
    {
        return $this->header;
    }
}
