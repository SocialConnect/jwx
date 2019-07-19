<?php
/**
 * SocialConnect project
 * @author: Patsura Dmitry https://github.com/ovr <talk@dmtry.me>
 */

namespace Test\JWX;

use SocialConnect\JWX\JWK;

class JWKTest extends AbstractTestCase
{
    public function testFromRSA256PublicKey()
    {
        $jwk = JWK::fromRSAPublicKeyFile(__DIR__ . '/assets/rs256.key.pub');

        parent::assertSame(
            [
                'kty' => 'RSA',
                'n' => 'w9p2cmLLIxIH_RloYqx3JbgWp1k4SIGU1yC7wbqRI7LELTTLifKhbyj9XuR2lVDxkIFGRizWnc6iZVZTRunHZQjwp537gub4Q6wK_pFu_rfdPC6AVHBw6Vo8hpEzrmPHwiPLqnwQuOLFD82oCAaSiB2FBMjyzF_kFNR0b7301q_gLP-5szQ4gGnfrmP0bIg_OxLlCxxXP1U232o_rfEvMfdMQGMHInX_m3IJ_kXqwkUlPzms2bictjnRvOX7-763qfoYUMlEe-5Ovghl-gWQzWP5r-21nuD9zLeid5j-9bznaI0G69iSYgw833PQFnbcwdxrs-Ixjlbmyp0op5b_IQ',
                'e' => 'AQAB',
                'alg' => 'RSA256',
            ],
            $jwk->toArray()
        );
    }

    public function testFromRSA384PublicKey()
    {
        $jwk = JWK::fromRSAPublicKeyFile(__DIR__ . '/assets/rs384.key.pub');

        parent::assertSame(
            [
                'kty' => 'RSA',
                'n' => 'vSfQKp95P9KlFosHmcjB7ZnwGv9S4Q_Jsflc6AVH1D8bUnB4Jfn4fxfWx7Wz4-a-9ulZtiJf7Fk9Pe3Qcel3z5fFEIGNqGDRgpMnHh93DbYGEW0XokS6ATGF_ijm87lC1xvjGIYB07o03gupKykHjQkX5PtA6pkOgzF1Pe4cxDcro_73R8_Kzi6FSsLfsrmE_kJBW63lV4FOnqKnFZw2Uw7Bc6UT0lmVyZuMr_QRK_H5A-ZJTA6ChgkGXepRIgbqA1xaiDZLnj7EZahxQMaWqygzlRKwkKCm3XT0C9jHoY9gW_PW_ZhO-pdFL1Wit8H_zE9oKGxpoNbRJZMjG4Vej5tF7bmHv9fi1RkSQiR_dQIy0PxjWWXQu1CFvHvFJiZv1rlHQcw5jPmjUxeTY2wdjR7mDTqkWs6qTKb3aQY3n_ITv-pnQs8FnDWOeTSCw47I8ZBd1bPXhy2Yp1h_vaLZQZACDWaMggp0uxpldbZcGykMdtmVAPwjBYmOEwBqYANt',
                'e' => 'AQAB',
                'alg' => 'RSA384',
            ],
            $jwk->toArray()
        );
    }

    public function testFromRSA512PublicKey()
    {
        $jwk = JWK::fromRSAPublicKeyFile(__DIR__ . '/assets/rs512.key.pub');

        parent::assertSame(
            [
                'kty' => 'RSA',
                'n' => 'tUhEJVPAIwGPIsyh7cYnKx809s7XnkUoG7D6T092L_URRf1kDHL6_2amwxG_HeFtqdT_J9oy6SU8C5qdqfXJcR75hTZ_pMcIna496tqGgWHOGHnRUZfXMRufuCfCX9i-RnEXAdE8z-dHZpKtRnU3rp9wmfiECzHipmbwzf445G_iJtWkenQbHt1_Budsjb8JdAitdRuZtOvreqFLh5aPL5DHhE1tT-RNIiDEbgyi4W49HtYw_m7MbzQfarM6ZumYY3NJiCEBeK7PcCNiW1F-KrNBONZ_d2pJ67XY6CodcBM8I_tdnUYgoKIydJGRKfD6bzyzanfCOBLOn56_et1BiBHpK3MfdUuxMRn4W2NP6hbwyLBH-Dzd_CWui0F4jOemZEEYNLZYFMHYqYVTdTZZ7RMXeQSd0iEbgEq1NACDC-EJLqfmhIAgC_OO9cMmAARCUKsgzvy_RlYb51Gn5FQx_3BsmzFuYDAI4z_NyR18OzaeupGyMpr0LHMGXQ1f8rbs7L-pfUZYkfNoiRr-UWyZGOZ5r6Vlzi_PdJNDDlWq2WLk6H3l_XF9pif3_LoAy-a0FKwdzwGjUgOtWmdU1eXXeQLlVXw05HTNLWU9WnyJn9wkD2FK7SEx3IVjrnVn_-P5TnfkaKG2qgPu4YWRiYatPpZiZgGdvKYf3q49Qm9Hhps',
                'e' => 'AQAB',
                'alg' => 'RSA512',
            ],
            $jwk->toArray()
        );
    }

    public function testFromRSA256PrivateKey()
    {
        $jwk = JWK::fromRSAPrivateKeyFile(__DIR__ . '/assets/rs256.key');

        parent::assertSame(
            [
                'kty' => 'RSA',
                'n' => 'w9p2cmLLIxIH_RloYqx3JbgWp1k4SIGU1yC7wbqRI7LELTTLifKhbyj9XuR2lVDxkIFGRizWnc6iZVZTRunHZQjwp537gub4Q6wK_pFu_rfdPC6AVHBw6Vo8hpEzrmPHwiPLqnwQuOLFD82oCAaSiB2FBMjyzF_kFNR0b7301q_gLP-5szQ4gGnfrmP0bIg_OxLlCxxXP1U232o_rfEvMfdMQGMHInX_m3IJ_kXqwkUlPzms2bictjnRvOX7-763qfoYUMlEe-5Ovghl-gWQzWP5r-21nuD9zLeid5j-9bznaI0G69iSYgw833PQFnbcwdxrs-Ixjlbmyp0op5b_IQ',
                'e' => 'AQAB',
                'd' => 'mWWIE_sw410CCMhXq8Es6MwQYi5NGOz1KLGonQmFGBKx-D47lOYGbswJ9sK15ikpqma2JcyEo8DuDLTaMNZ1p7qi0oW4MkS4-jfLvKsn5jUYAETjmj8fEIXule8wLUxVbsceg378kfJ7Ke-HxhFvv1BvmNnS4SPRvkbQk5ySIXrr5wIXRAwAR9DtvGeJ-FbBHuymekwMww3QIrkxz7RRPZhkKNHNqFB85sNqVObGKiJ-uYnFaJW9_WKxWiWVK5B4sQTOfvstVYQn_EvIKON9fgV9C2vdp7-OE1k9Xq06SbHeczOy-D95McZPIdurKu9l_9ZX8558MlsfEFXq9rMmKQ',
                'alg' => 'RSA256',
            ],
            $jwk->toArray()
        );
    }

    public function testFromRSA384PrivateKey()
    {
        $jwk = JWK::fromRSAPrivateKeyFile(__DIR__ . '/assets/rs384.key');

        parent::assertSame(
            [
                'kty' => 'RSA',
                'n' => 'vSfQKp95P9KlFosHmcjB7ZnwGv9S4Q_Jsflc6AVH1D8bUnB4Jfn4fxfWx7Wz4-a-9ulZtiJf7Fk9Pe3Qcel3z5fFEIGNqGDRgpMnHh93DbYGEW0XokS6ATGF_ijm87lC1xvjGIYB07o03gupKykHjQkX5PtA6pkOgzF1Pe4cxDcro_73R8_Kzi6FSsLfsrmE_kJBW63lV4FOnqKnFZw2Uw7Bc6UT0lmVyZuMr_QRK_H5A-ZJTA6ChgkGXepRIgbqA1xaiDZLnj7EZahxQMaWqygzlRKwkKCm3XT0C9jHoY9gW_PW_ZhO-pdFL1Wit8H_zE9oKGxpoNbRJZMjG4Vej5tF7bmHv9fi1RkSQiR_dQIy0PxjWWXQu1CFvHvFJiZv1rlHQcw5jPmjUxeTY2wdjR7mDTqkWs6qTKb3aQY3n_ITv-pnQs8FnDWOeTSCw47I8ZBd1bPXhy2Yp1h_vaLZQZACDWaMggp0uxpldbZcGykMdtmVAPwjBYmOEwBqYANt',
                'e' => 'AQAB',
                'd' => 'Rwq67icy_Lt6cXsKAcIaw8g7G4ilcg3h7MwBDstc7OQ-uLmxBmJZ6DHl4t_ljkTNmCKQJQ3IBRaHH8k_rmjHLNqNkuN1drXWOjpWSMP8jNO-d7EHXVR-n5AgCRMHmqYL6op4wm8iJIkc7gBnKuSgB2JQ7RlIilOt1awvonDZsQAfjdpmuTvbqZBjU27ZYWC4CF6N-YbYSgMwqffg1Qb0iEFUesCXLzuiPDQFpNf_0wdwRPyqrrwMXZbqIz-r9SGvAQRbwlum0-lVhZafTyWsol1cYA11a0-x9vXaU8VRnFeiNum7IdKYDs--jOhJSu5tsL9k2Xc0gM7egXWANVNelOS1uJ_TyMVrms0K15Oy7MwurJM3R_vRJJv7dK0_Ldxnm0aXBslYvjxZTPxLCsYOEiQTsFcKvce76tV-IaXhUn4OQ1GoKjW6Xd9yNH3wG5M0oT_r3FltSy6cg4UcC6Xc5QK_Azs1kebbzTKlA707-loxFqvDLYbfhqx914zfW-9B',
                'alg' => 'RSA384',
            ],
            $jwk->toArray()
        );
    }

    public function testFromRSA512PrivateKey()
    {
        $jwk = JWK::fromRSAPrivateKeyFile(__DIR__ . '/assets/rs512.key');

        parent::assertSame(
            [
                'kty' => 'RSA',
                'n' => 'tUhEJVPAIwGPIsyh7cYnKx809s7XnkUoG7D6T092L_URRf1kDHL6_2amwxG_HeFtqdT_J9oy6SU8C5qdqfXJcR75hTZ_pMcIna496tqGgWHOGHnRUZfXMRufuCfCX9i-RnEXAdE8z-dHZpKtRnU3rp9wmfiECzHipmbwzf445G_iJtWkenQbHt1_Budsjb8JdAitdRuZtOvreqFLh5aPL5DHhE1tT-RNIiDEbgyi4W49HtYw_m7MbzQfarM6ZumYY3NJiCEBeK7PcCNiW1F-KrNBONZ_d2pJ67XY6CodcBM8I_tdnUYgoKIydJGRKfD6bzyzanfCOBLOn56_et1BiBHpK3MfdUuxMRn4W2NP6hbwyLBH-Dzd_CWui0F4jOemZEEYNLZYFMHYqYVTdTZZ7RMXeQSd0iEbgEq1NACDC-EJLqfmhIAgC_OO9cMmAARCUKsgzvy_RlYb51Gn5FQx_3BsmzFuYDAI4z_NyR18OzaeupGyMpr0LHMGXQ1f8rbs7L-pfUZYkfNoiRr-UWyZGOZ5r6Vlzi_PdJNDDlWq2WLk6H3l_XF9pif3_LoAy-a0FKwdzwGjUgOtWmdU1eXXeQLlVXw05HTNLWU9WnyJn9wkD2FK7SEx3IVjrnVn_-P5TnfkaKG2qgPu4YWRiYatPpZiZgGdvKYf3q49Qm9Hhps',
                'e' => 'AQAB',
                'd' => 'GoNcPB1Yn4YN2igVksIFXoAs7d_olyRELnCe21Si03bDNPpPVKbIYOwxfZwt2H_s2wbk3n5CLekdNBFD9-STtrCyC7KhzoaxkuY19hBJ1chpLRk77PQJLAx_Op7OBdicU48cr05b14ha3_yZzRE9uJNnE43OOhjsriumEmqZBYf7inR6ntI2WThJ6MeWD9Ed39OZEuSbgWNzyDao5ka14F4LYCU21JVuVox2TiYY-GF4HPd0qPGpgqYb5i4aX4zQldL5sSgqn-zpN9xk-Tgc_L_EzTxJ3jw0XX32IFZwgcC-bgDIe0UTZoryWCwmD_1Hk1dMYkjrpenSQHQmSyDrAW2LFJ5CP8MuXGhgZkxxA6_5vPKgxrJBCQzX41Lk2pntHOHw9-DlJdkwumtQCBYhbtU0f-ApGwsv-Kbnf3AtB2wBwcgtjfAsgzzQPQ-CslhzWZaaFS6c83jwZHrKIUA6mJf_KGSokhLzVpDWtQcyDuXB4BMNK5j_LFPzrw9CsK94ZwVyArUzdBUmKoIZ9_n22Io-vJ3xRjsTWaWVOHrgj9M4XxRVMWgv-ZDDrgczAn9BAmfMA9mgYE2Ba7DOAHUNQsXS3-p0i2kCeCOopdzDwSe2sZQVE__xXoBC3wBTpFK3xb-s71hkbBIVGolzS7kYFV4hxRDVH-Q7Ml-UbG3PU9k',
                'alg' => 'RSA512',
            ],
            $jwk->toArray()
        );
    }
}
