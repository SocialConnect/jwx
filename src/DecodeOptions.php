<?php
/**
 * SocialConnect project
 * @author: Patsura Dmitry https://github.com/ovr <talk@dmtry.me>
 */
declare(strict_types=1);

namespace SocialConnect\JWX;

class DecodeOptions
{
    /**
     * @var array
     */
    protected $allowedAlgorithms;

    /**
     * @var array|null
     */
    protected $jwkSet = null;

    /**
     * @var string|null
     */
    protected $secretOrKey;

    /**
     * All algorithms without NONE
     */
    const SECURE_ALGORITHMS = [
        'HS256',
        'HS384',
        'HS512',
        //
        'RS256',
        'RS384',
        'RS512',
        //
        'ES256',
        'ES384',
        'ES512',
    ];

    /**
     * @param array $allowedAlgorithms
     * @param string|null $secretOrKey
     */
    public function __construct(array $allowedAlgorithms = self::SECURE_ALGORITHMS, string $secretOrKey = null)
    {
        $this->allowedAlgorithms = $allowedAlgorithms;
        $this->secretOrKey = $secretOrKey;
    }

    /**
     * @param string $algorithm
     * @return bool
     */
    public function isAllowedAlgorithms(string $algorithm): bool
    {
        return in_array($algorithm, $this->allowedAlgorithms, true);
    }

    /**
     * @return bool
     */
    public function hasJwkSet(): bool
    {
        return $this->jwkSet !== null;
    }

    /**
     * @return array|null
     */
    public function getJwkSet()
    {
        return $this->jwkSet;
    }

    /**
     * @param array $jwkSet
     */
    public function setJwkSet(array $jwkSet)
    {
        $this->jwkSet = $jwkSet;
    }

    /**
     * @return string|null
     */
    public function getSecretOrKey()
    {
        return $this->secretOrKey;
    }
}
