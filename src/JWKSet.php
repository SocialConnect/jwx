<?php
/**
 * SocialConnect project
 * @author: Patsura Dmitry https://github.com/ovr <talk@dmtry.me>
 */
declare(strict_types=1);

namespace SocialConnect\JWX;

use SocialConnect\JWX\Exception\RuntimeException;

class JWKSet
{
    /**
     * @var array<string, array>
     */
    protected $keys;

    /**
     * @param array<string, array> $parameters
     */
    public function __construct(array $parameters)
    {
        if (isset($parameters['keys'])) {
            $this->keys = $parameters['keys'];
        } else {
            throw new \InvalidArgumentException('JWKs must define keys');
        }
    }

    /**
     * @param string $kid
     * @return JWK
     */
    public function findKeyByKid(string $kid)
    {
        foreach ($this->keys as $jwk) {
            if (isset($jwk['kid']) && $jwk['kid'] === $kid) {
                return new JWK($jwk);
            }
        }

        throw new RuntimeException('Unknown key');
    }
}
