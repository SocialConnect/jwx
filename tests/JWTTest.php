<?php
/**
 * SocialConnect project
 * @author: Patsura Dmitry https://github.com/ovr <talk@dmtry.me>
 */

namespace Test\JWX;

use DateTime;
use SocialConnect\JWX\DecodeOptions;
use SocialConnect\JWX\EncodeOptions;
use SocialConnect\JWX\Exception\ExpiredJWT;
use SocialConnect\JWX\Exception\InvalidJWT;
use SocialConnect\JWX\JWK;
use SocialConnect\JWX\JWT;

class JWTTest extends AbstractTestCase
{
    /**
     * @return array
     */
    protected function getJWKSet()
    {
        return [
            [
                'kid' => 'testSigKey',
                'kty' => 'RS256',
                'n' => 'TEST',
                'e' => 'TEST'
            ]
        ];
    }

    /**
     * @return array
     */
    protected function getTestHeader(string $alg = 'RS256', string $kid = 'testSigKey')
    {
        return [
            'alg' => $alg,
            'kid' => $kid
        ];
    }

    public function testValidateClaimsSuccess()
    {
        $token = new JWT(
            array(
                'nbf' => time(),
                'iat' => time(),
                'exp' => time() + 20,
            ),
            $this->getTestHeader()
        );

        self::callProtectedMethod(
            $token,
            'validateClaims'
        );

        // to skip warning
        parent::assertTrue(true);
    }

    public function testValidateClaimsNbfFail()
    {
        $token = new JWT(
            array(
                'nbf' => $nbf = time() + 10,
                'iat' => time(),
                'exp' => time() + 20,
            ),
            $this->getTestHeader()
        );

        parent::expectException(InvalidJWT::class);
        parent::expectExceptionMessage(sprintf(
            'nbf (Not Fefore) claim is not valid %s',
            date(DateTime::RFC3339, $nbf)
        ));

        self::callProtectedMethod(
            $token,
            'validateClaims'
        );
    }

    public function testValidateClaimsNbfScrew()
    {
        JWT::$screw = 30;

        $token = new JWT(
            array(
                'nbf' => $nbf = time() + 10,
                'iat' => time(),
                'exp' => time() + 20,
            ),
            $this->getTestHeader()
        );

        self::callProtectedMethod(
            $token,
            'validateClaims'
        );

        JWT::$screw = 0;

        // to skip warning
        parent::assertTrue(true);
    }

    public function testValidateClaimsExpNotNumeric()
    {
        $token = new JWT(
            array(
                'nbf' => time(),
                'iat' => time(),
                'exp' => 'invalid',
            ),
            $this->getTestHeader()
        );

        parent::expectException(InvalidJWT::class);
        parent::expectExceptionMessage('exp (Expiration Time) must be numeric');

        self::callProtectedMethod(
            $token,
            'validateClaims'
        );
    }

    public function testValidateClaimsExpExpired()
    {
        $token = new JWT(
            array(
                'nbf' => time(),
                'iat' => time(),
                'exp' => $exp = time() - 20,
            ),
            $this->getTestHeader()
        );

        parent::expectException(ExpiredJWT::class);
        parent::expectExceptionMessage(
            sprintf(
                'exp (Expiration Time) claim is not valid %s',
                date(DateTime::RFC3339, $exp)
            )
        );

        self::callProtectedMethod(
            $token,
            'validateClaims'
        );
    }

    public function testValidateHeaderSuccess()
    {
        $token = new JWT(
            [],
            $this->getTestHeader()
        );

        $options = new DecodeOptions(['RS256']);
        $options->setJwkSet([]);

        self::callProtectedMethod(
            $token,
            'validateHeader',
            $options
        );

        // to skip warning
        parent::assertTrue(true);
    }

    public function testValidateHeaderNoAlg()
    {
        $token = new JWT(
            [],
            [
                'kid' => 'testSigKey'
            ]
        );

        parent::expectException(InvalidJWT::class);
        parent::expectExceptionMessage('No alg inside header');

        self::callProtectedMethod(
            $token,
            'validateHeader',
            new DecodeOptions([])
        );
    }

    public function testValidateHeaderNoKid()
    {
        $token = new JWT(
            [],
            [
                'alg' => 'RS256'
            ]
        );

        parent::expectException(InvalidJWT::class);
        parent::expectExceptionMessage('No kid inside header');

        $options = new DecodeOptions(['RS256']);
        $options->setJwkSet([]);

        self::callProtectedMethod(
            $token,
            'validateHeader',
            $options
        );
    }

    public function testDecodeWrongNumberOfSegments()
    {
        parent::expectException(InvalidJWT::class);
        parent::expectExceptionMessage('Wrong number of segments');

        JWT::decode(
            'lol',
            new DecodeOptions([])
        );
    }

    public function testEncodeToDecodeSuccess()
    {
        $kid = 'super-kid-' . time();
        $jwk = [
            'kid' => $kid,
            'kty' => 'HS512',
            'n' => 'test',
            'e' => 'test'
        ];

        $payload = [
            'uid' => '2955b34c-7a3b-4d96-9fd1-2930c18f9989'
        ];

        $token = new JWT($payload, ['kid' => $kid]);
        $jwtAsString = $token->encode((new JWK($jwk))->getPublicKey(), 'HS512', new EncodeOptions());

        $decodeOptions = new DecodeOptions(['HS512'], 'TEST');
        $decodeOptions->setJwkSet([$jwk]);

        $jwt = JWT::decode($jwtAsString, $decodeOptions);

        parent::assertSame($payload, $jwt->getPayload());

        $headers = $jwt->getHeader();
        parent::assertArrayHasKey('kid', $headers);
        parent::assertArrayHasKey('alg', $headers);
    }
}
