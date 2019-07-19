<?php
/**
 * SocialConnect project
 * @author: Patsura Dmitry https://github.com/ovr <talk@dmtry.me>
 */
declare(strict_types=1);

namespace SocialConnect\JWX;

use SocialConnect\JWX\Exception\InvalidJWK;
use SocialConnect\JWX\Exception\RuntimeException;
use SocialConnect\JWX\Exception\UnsupportedJWK;

class JWK
{
    /**
     * @link https://tools.ietf.org/html/rfc7517#section-4.1
     *
     * The "kty" (key type) parameter identifies the cryptographic algorithm
     * family used with the key, such as "RSA" or "EC"
     *
     * @var string
     */
    protected $kty;

    /**
     * @link https://tools.ietf.org/html/rfc7517#section-4.4
     *
     * The "alg" value is a case-sensitive ASCII string. Use of this member is OPTIONAL.
     *
     * @var string
     */
    protected $alg;

    /**
     * modulus
     *
     * @link https://tools.ietf.org/html/rfc7517#section-9.3
     *
     * @var string
     */
    protected $n;

    /**
     * public exponent
     *
     * @link https://tools.ietf.org/html/rfc7517#section-9.3
     *
     * @var string
     */
    protected $e;

    /**
     * private exponent
     *
     * @link https://tools.ietf.org/html/rfc7517#section-9.3
     *
     * @var string|null
     */
    protected $d;

    /**
     * @param array $parameters
     * @throws InvalidJWK
     */
    public function __construct($parameters)
    {
        if (!isset($parameters['kty'])) {
            throw new InvalidJWK('Unknown kty');
        }

        $this->kty = $parameters['kty'];

        switch ($this->kty) {
            case 'RSA':
                $this->parseRSAKey($parameters);
                break;
            default:
                throw new UnsupportedJWK("Unsupported kty, {$this->kty}");
        }
    }

    /**
     * @return string
     */
    public function getPublicKey()
    {
        $modulus = JWT::urlsafeB64Decode($this->n);
        $publicExponent = JWT::urlsafeB64Decode($this->e);

        $components = array(
            'modulus' => pack('Ca*a*', 2, self::encodeLength(strlen($modulus)), $modulus),
            'publicExponent' => pack('Ca*a*', 2, self::encodeLength(strlen($publicExponent)), $publicExponent)
        );

        $publicKey = pack(
            'Ca*a*a*',
            48,
            self::encodeLength(strlen($components['modulus']) + strlen($components['publicExponent'])),
            $components['modulus'],
            $components['publicExponent']
        );

        // sequence(oid(1.2.840.113549.1.1.1), null)) = rsaEncryption.
        $rsaOID = pack('H*', '300d06092a864886f70d0101010500'); // hex version of MA0GCSqGSIb3DQEBAQUA
        $publicKey = chr(0) . $publicKey;
        $publicKey = chr(3) . self::encodeLength(strlen($publicKey)) . $publicKey;
        $publicKey = pack(
            'Ca*a*',
            48,
            self::encodeLength(strlen($rsaOID . $publicKey)),
            $rsaOID . $publicKey
        );

        $publicKey = "-----BEGIN PUBLIC KEY-----\r\n" .
            chunk_split(base64_encode($publicKey), 64) .
            '-----END PUBLIC KEY-----';

        return $publicKey;
    }

    /**
     * DER-encode the length
     *
     * DER supports lengths up to (2**8)**127, however, we'll only support lengths up to (2**8)**4.  See
     * {@link http://itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf#p=13 X.690 paragraph 8.1.3} for more information.
     *
     * @access private
     * @param int $length
     * @return string
     */
    private static function encodeLength($length)
    {
        if ($length <= 0x7F) {
            return chr($length);
        }

        $temp = ltrim(pack('N', $length), chr(0));
        return pack('Ca*', 0x80 | strlen($temp), $temp);
    }

    /**
     * @return string
     */
    public function getKty(): string
    {
        return $this->kty;
    }

    protected function parseRSAKey(array $parameters)
    {
        if (!isset($parameters['n'])) {
            throw new InvalidJWK('Unknown n');
        }

        $this->n = $parameters['n'];

        if (!isset($parameters['e'])) {
            throw new InvalidJWK('Unknown e');
        }

        $this->e = $parameters['e'];

        if (isset($parameters['d'])) {
            $this->d = $parameters['d'];
        }

        if (isset($parameters['alg'])) {
            $this->alg = $parameters['alg'];
        }
    }

    /**
     * @param string $file
     * @return JWK
     */
    public static function fromRSAPublicKeyFile(string $file): JWK
    {
        $contentOrFalse = file_get_contents($file);
        if ($contentOrFalse === false) {
            throw new RuntimeException('Unable to read public key');
        }

        return self::fromRSAPublicKey($contentOrFalse);
    }

    /**
     * @param string $content
     * @return JWK
     */
    public static function fromRSAPublicKey(string $content): JWK
    {
        $publicKeyOrFalse = openssl_pkey_get_public($content);
        if ($publicKeyOrFalse === false) {
            throw new RuntimeException('Unable to load public key');
        }

        $dataOrFalse = openssl_pkey_get_details($publicKeyOrFalse);
        if ($dataOrFalse === false) {
            throw new RuntimeException('Unable to load data from public key');
        }

        return new JWK([
            'kty' => 'RSA',
            'alg' => 'RSA' . ($dataOrFalse['bits'] / 8),
            'e' => rtrim(str_replace(['+', '/'], ['-', '_'], base64_encode($dataOrFalse['rsa']['e'])), '='),
            'n' => rtrim(str_replace(['+', '/'], ['-', '_'], base64_encode($dataOrFalse['rsa']['n'])), '='),
        ]);
    }

    /**
     * @param string $file
     * @return JWK
     */
    public static function fromRSAPrivateKeyFile(string $file): JWK
    {
        $contentOrFalse = file_get_contents($file);
        if ($contentOrFalse === false) {
            throw new RuntimeException('Unable to read private key');
        }

        return self::fromRSAPrivateKey($contentOrFalse);
    }

    /**
     * @param string $content
     * @return JWK
     */
    public static function fromRSAPrivateKey(string $content)
    {
        $privateKeyOrFalse = openssl_pkey_get_private($content);
        if ($privateKeyOrFalse === false) {
            throw new RuntimeException('Unable to private public key');
        }

        $dataOrFalse = openssl_pkey_get_details($privateKeyOrFalse);
        if ($dataOrFalse === false) {
            throw new RuntimeException('Unable to load data from private key');
        }

        return new JWK([
            'kty' => 'RSA',
            'alg' => 'RSA' . ($dataOrFalse['bits'] / 8),
            'e' => rtrim(str_replace(['+', '/'], ['-', '_'], base64_encode($dataOrFalse['rsa']['e'])), '='),
            'n' => rtrim(str_replace(['+', '/'], ['-', '_'], base64_encode($dataOrFalse['rsa']['n'])), '='),
            'd' => rtrim(str_replace(['+', '/'], ['-', '_'], base64_encode($dataOrFalse['rsa']['d'])), '='),
        ]);
    }

    public function toArray()
    {
        switch ($this->kty) {
            case 'RSA':
                $info = [
                    'kty' => 'RSA',
                    'n' => $this->n,
                    'e' => $this->e,
                ];

                if ($this->d) {
                    $info['d'] = $this->d;
                }

                if ($this->alg) {
                    $info['alg'] = $this->alg;
                }

                return $info;
            default:
                throw new RuntimeException('Unsupported');
        }
    }
}
