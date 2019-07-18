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
     * @param array<string, array> $keys
     */
    public function __construct(array $keys)
    {
        $this->keys = array_map(static function ($key) {
            return new JWK($key);
        }, $keys);
    }

    /**
     * @param string $kid
     * @return JWK
     */
    public function findKeyByKind(string $kid)
    {
        foreach ($this->keys as $key => $jwk) {
            if ($key === $kid) {
                return $jwk;
            }
        }

        throw new RuntimeException('Unknown key');
    }
}
