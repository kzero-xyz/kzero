use crate::error::{ZkAuthError, ZkAuthResult};
use sp_core::ConstU32;
use sp_runtime::BoundedVec;
use sp_std::result::Result;

const GOOGLE_JWK_LIST: [JWK; 2] = [
    JWK {
        kty: "RSA",
        e: "AQAB",
        kid: "1f40f0a8ef3d880978dc82f25c3ec317c6a5b781",
        n: "tgkwz0K80MycaI2Dz_jHkErJ_IHUPTlx4LR_6wltAHQW_ZwhMzINNH8vbWo8P5F2YLDiIbuslF9y7Q3izsPX3XWQyt6LI8ZT4gmGXQBumYMKx2VtbmTYIysKY8AY7x5UCDO-oaAcBuKQvWc5E31kXm6d6vfaEZjrMc_KT3DsFdN0LcAkB-Q9oYcVl7YEgAN849ROKUs6onf7eukj1PHwDzIBgA9AExJaKen0wITvxQv3H_BRXB7m6hFkLbK5Jo18gl3UxJ7Em29peEwi8Psn7MuI7CwhFNchKhjZM9eaMX27tpDPqR15-I6CA5Zf94rabUGWYph5cFXKWPPr8dskQQ",
        alg: "RS256"
    },
    JWK {
        kty: "RSA",
        n: "qwrzl06fwB6OIm62IxNG7NXNIDmgdBrvf09ob2Gsp6ZmAXgU4trHPUYrdBaAlU5aHpchXCf_mVL-U5dzRqeVFQsVqsj4PEIE6E5OPw8EwumP2fzLQSswpkKmJJKFcdncfQ730QBonRUEhKkIbiYdicJl5yTkORd0_BmfdLV98r-sEwEHN4lzTJ15-yw90ob_R6vAH4wPyCSN3Xe5_zV6R4ENL2NlKn2HT9lbV7HhtQongea8wfnthUhdZH38kI4SS5nAaCVNxEAzlvJtUIdCpSgjUgcbah-DwY39l4D800kLxkcF2CGXPSmpF8GPs1aWSsYupY8sTSy9qCFJFPFx8Q",
        kid: "48a63bc4767f8550a532dc630cf7eb49ff397e7c",
        e: "AQAB",
        alg: "RS256"
    }
];

const TWITCH_JWK_LIST: [JWK; 1] = [
    JWK {
        alg: "RS256",
        e: "AQAB",
        kid: "1",
        kty: "RSA",
        n: "6lq9MQ-q6hcxr7kOUp-tHlHtdcDsVLwVIw13iXUCvuDOeCi0VSuxCCUY6UmMjy53dX00ih2E4Y4UvlrmmurK0eG26b-HMNNAvCGsVXHU3RcRhVoHDaOwHwU72j7bpHn9XbP3Q3jebX6KIfNbei2MiR0Wyb8RZHE-aZhRYO8_-k9G2GycTpvc-2GBsP8VHLUKKfAs2B6sW3q3ymU6M0L-cFXkZ9fHkn9ejs-sqZPhMJxtBPBxoUIUQFTgv4VXTSv914f_YkNw-EjuwbgwXMvpyr06EyfImxHoxsZkFYB-qBYHtaMxTnFsZBr6fn8Ha2JqT1hoP7Z5r5wxDu3GQhKkHw",

    }
];

const FACEBOOK_JWK_LIST: [JWK; 2] = [
    JWK {
        kid: "e30332ccd69b4bb991b043dbc16aa560913f28ad",
        kty: "RSA",
        alg: "RS256",
        n: "m3TQkyJTnTm49L7NM1c7_VwFeBhxmaG1TzIOZIu_QxO8SfvJSQut4Q0OakHyiXSiSNigDPKH0wjtIAwwD2D1CVjjdalVRx1U_9JjuF0t51PpZ3C5VwZk8dhMo3iLnOGIrBsJdsA-VStmn1jqovqHf6KV1qdgMabBkwWGfBvQuAPRUUXZViEOATKmd_TqgsAZqpI-mplIGqxB-dK1IIiJXAmmil6GYqajsjS18NKoMohH3Xz4HGr5oo7cvDJBFrFWcNvA2vQ7QYhwMUu88GyJ3cFmu3LpYYgJ-toEVmwraXyx8rZ1AdKrmFjCVTYPbm7G4XjdVFw0I2Y0V1EJIRgfWw",
        e: "AQAB"
    },
    JWK {
        kid: "076da2308aaf2efdd354964b71fcac53c7f4b2b4",
        kty: "RSA",
        alg: "RS256",
        n: "vl9iKWWFYhHisLklv0U_-LOK1NwwTKGaAx2SdgvqrTH-JrbHsb_o-gCk4GVGVajEsV2IGxTPmpB0Y8ag5n8jSP75AL814SUAArLwBRo1auuBc5AxYCa02kf99QJjKlNvK4BWX7L8j7bqzNEZGKbP4_3qEeL98rU_T_7-Q19I-WFJNHy_I7GiaTCWn1h1EXomSRFyhUJxVk6nQ4dnVOlBlIIga88ExF8S8rK7HW19Xa-wCEEHoPp_H3HPTwSwj_HgvE_mm0U65wVxKaZ0zLMGP1fV9ZG0PSCnsP1DWl33ViTI0pf8bAHSu3r_oDUAjIOnKlmfqfoDy58SPcXlU2oalw",
        e: "AQAB"
    }
];

const KAKAO_JWT_LIST: [JWK; 2] = [
    JWK {
        kid: "3f96980381e451efad0d2ddd30e3d3",
        kty: "RSA",
        alg: "RS256",
        n: "q8zZ0b_MNaLd6Ny8wd4cjFomilLfFIZcmhNSc1ttx_oQdJJZt5CDHB8WWwPGBUDUyY8AmfglS9Y1qA0_fxxs-ZUWdt45jSbUxghKNYgEwSutfM5sROh3srm5TiLW4YfOvKytGW1r9TQEdLe98ork8-rNRYPybRI3SKoqpci1m1QOcvUg4xEYRvbZIWku24DNMSeheytKUz6Ni4kKOVkzfGN11rUj1IrlRR-LNA9V9ZYmeoywy3k066rD5TaZHor5bM5gIzt1B4FmUuFITpXKGQZS5Hn_Ck8Bgc8kLWGAU8TzmOzLeROosqKE0eZJ4ESLMImTb2XSEZuN1wFyL0VtJw",
        e: "AQAB"
    },
    JWK {
        kid: "9f252dadd5f233f93d2fa528d12fea",
        kty: "RSA",
        alg: "RS256",
        n: "qGWf6RVzV2pM8YqJ6by5exoixIlTvdXDfYj2v7E6xkoYmesAjp_1IYL7rzhpUYqIkWX0P4wOwAsg-Ud8PcMHggfwUNPOcqgSk1hAIHr63zSlG8xatQb17q9LrWny2HWkUVEU30PxxHsLcuzmfhbRx8kOrNfJEirIuqSyWF_OBHeEgBgYjydd_c8vPo7IiH-pijZn4ZouPsEg7wtdIX3-0ZcXXDbFkaDaqClfqmVCLNBhg3DKYDQOoyWXrpFKUXUFuk2FTCqWaQJ0GniO4p_ppkYIf4zhlwUYfXZEhm8cBo6H2EgukntDbTgnoha8kNunTPekxWTDhE5wGAt6YpT4Yw",
        e: "AQAB"
    }
];

const APPLE_JWT_LIST: [JWK; 3] = [
    JWK {
        kty: "RSA",
        kid: "lVHdOx8ltR",
        alg: "RS256",
        n: "nXDu9MPf6dmVtFbDdAaal_0cO9ur2tqrrmCZaAe8TUWHU8AprhJG4DaQoCIa4UsOSCbCYOjPpPGGdE_p0XeP1ew55pBIquNhNtNNEMX0jNYAKcA9WAP1zGSkvH5m39GMFc4SsGiQ_8Szht9cayJX1SJALEgSyDOFLs-ekHnexqsr-KPtlYciwer5jaNcW3B7f9VNp1XCypQloQwSGVismPHwDJowPQ1xOWmhBLCK50NV38ZjobUDSBbCeLYecMtsdL5ZGv-iufddBh3RHszQiD2G-VXoGOs1yE33K4uAto2F2bHVcKOUy0__9qEsXZGf-B5ZOFucUkoN7T2iqu2E2Q",
        e: "AQAB"
    },
    JWK {
        kty: "RSA",
        kid: "W6WcOKB",
        alg: "RS256",
        n: "2Zc5d0-zkZ5AKmtYTvxHc3vRc41YfbklflxG9SWsg5qXUxvfgpktGAcxXLFAd9Uglzow9ezvmTGce5d3DhAYKwHAEPT9hbaMDj7DfmEwuNO8UahfnBkBXsCoUaL3QITF5_DAPsZroTqs7tkQQZ7qPkQXCSu2aosgOJmaoKQgwcOdjD0D49ne2B_dkxBcNCcJT9pTSWJ8NfGycjWAQsvC8CGstH8oKwhC5raDcc2IGXMOQC7Qr75d6J5Q24CePHj_JD7zjbwYy9KNH8wyr829eO_G4OEUW50FAN6HKtvjhJIguMl_1BLZ93z2KJyxExiNTZBUBQbbgCNBfzTv7JrxMw",
        e: "AQAB"
    },
    JWK {
        kty: "RSA",
        kid: "fh6Bs8C",
        alg: "RS256",
        n: "u704gotMSZc6CSSVNCZ1d0S9dZKwO2BVzfdTKYz8wSNm7R_KIufOQf3ru7Pph1FjW6gQ8zgvhnv4IebkGWsZJlodduTC7c0sRb5PZpEyM6PtO8FPHowaracJJsK1f6_rSLstLdWbSDXeSq7vBvDu3Q31RaoV_0YlEzQwPsbCvD45oVy5Vo5oBePUm4cqi6T3cZ-10gr9QJCVwvx7KiQsttp0kUkHM94PlxbG_HAWlEZjvAlxfEDc-_xZQwC6fVjfazs3j1b2DZWsGmBRdx1snO75nM7hpyRRQB4jVejW9TuZDtPtsNadXTr9I5NjxPdIYMORj9XKEh44Z73yfv0gtw",
        e: "AQAB"
    }
];

const SLACK_JWT_LIST: [JWK; 1] =[
    JWK {
        e: "AQAB",
        n: "zQqzXfb677bpMKw0idKC5WkVLyqk04PWMsWYJDKqMUUuu_PmzdsvXBfHU7tcZiNoHDuVvGDqjqnkLPEzjXnaZY0DDDHvJKS0JI8fkxIfV1kNy3DkpQMMhgAwnftUiSXgb5clypOmotAEm59gHPYjK9JHBWoHS14NYEYZv9NVy0EkjauyYDSTz589aiKU5lA-cePG93JnqLw8A82kfTlrJ1IIJo2isyBGANr0YzR-d3b_5EvP7ivU7Ph2v5JcEUHeiLSRzIzP3PuyVFrPH659Deh-UAsDFOyJbIcimg9ITnk5_45sb_Xcd_UN6h5I7TGOAFaJN4oi4aaGD4elNi_K1Q",
        kty: "RSA",
        kid: "mB2MAyKSn555isd0EbdhKx6nkyAi9xLq8rvCEb_nOyY",
        alg: "RS256"
}

];

use super::*;
#[derive(
    Encode,
    Decode,
    RuntimeDebug,
    MaxEncodedLen,
    TypeInfo,
    Clone,
    Copy,
    Eq,
    PartialEq,
    PartialOrd,
    Ord
)]
pub enum JWKProvider {
    /// See https://accounts.google.com/.well-known/openid-configuration
    Google,
    /// See https://id.twitch.tv/oauth2/.well-known/openid-configuration
    Twitch,
    /// See https://www.facebook.com/.well-known/openid-configuration/
    Facebook,
    /// See https://kauth.kakao.com/.well-known/openid-configuration
    Kakao,
    /// See https://appleid.apple.com/.well-known/openid-configuration
    Apple,
    /// See https://slack.com/.well-known/openid-configuration
    Slack,
}

impl JWKProvider {
    fn from_utf8_slice(s: &[u8]) -> Result<Self, ZkAuthError> {
        match s {
            b"Google" => Ok(Self::Google),
            b"Twitch" => Ok(Self::Twitch),
            b"Facebook" => Ok(Self::Facebook),
            b"Kakao" => Ok(Self::Kakao),
            b"Apple" => Ok(Self::Apple),
            b"Slack" => Ok(Self::Slack),
            _ => Err(ZkAuthError::InvalidInput),
        }
    }
}

/// Key to identify a JWK, consists of iss and kid.
#[derive(
    Encode,
    Decode,
    RuntimeDebug,
    MaxEncodedLen,
    TypeInfo,
    Clone,
    Eq,
    PartialEq,
    PartialOrd,
    Ord
)]
pub struct JwkId {
    /// OIDC provider.
    pub provider: JWKProvider,
    /// kid string that identifies the JWK.
    pub kid: BoundedVec<u8, ConstU32<256>>,
}

impl JwkId {
    /// Create a new JwkId.
    pub fn new(provider: JWKProvider, kid: BoundedVec<u8, ConstU32<256>>) -> Self {
        Self { provider, kid }
    }
}

/// Struct that contains info for a JWK. A list of them for different kids can
/// be retrieved from the JWK endpoint (e.g. <https://www.googleapis.com/oauth2/v3/certs>).
/// The JWK is used to verify the JWT token.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(PartialEq, Eq, Hash, Debug, Clone, PartialOrd, Ord)]
pub struct JWK {
    /// Key type parameter, https://datatracker.ietf.org/doc/html/rfc7517#section-4.1
    pub kty: &'static str,
    // Key Id
    pub kid: &'static str,
    /// RSA public exponent, https://datatracker.ietf.org/doc/html/rfc7517#section-9.3
    pub e: &'static str,
    /// RSA modulus, https://datatracker.ietf.org/doc/html/rfc7517#section-9.3
    pub n: &'static str,
    /// Algorithm parameter, https://datatracker.ietf.org/doc/html/rfc7517#section-4.4
    pub alg: &'static str,
}

pub fn get_modulo(jwk_id: &JwkId) -> ZkAuthResult<JWK> {
    let jwk_list = match jwk_id.provider {
        JWKProvider::Google => GOOGLE_JWK_LIST.to_vec(),
        JWKProvider::Twitch => TWITCH_JWK_LIST.to_vec(),
        JWKProvider::Facebook => FACEBOOK_JWK_LIST.to_vec(),
        JWKProvider::Kakao => KAKAO_JWT_LIST.to_vec(),
        JWKProvider::Apple => APPLE_JWT_LIST.to_vec(),
        JWKProvider::Slack => SLACK_JWT_LIST.to_vec(),
    };

    jwk_list
        .into_iter()
        .find(|jwk| {
            jwk_id.kid
                == BoundedVec::<u8, ConstU32<256>>::truncate_from(jwk.kid.as_bytes().to_vec())
        })
        .ok_or(ZkAuthError::JWKNotFound)
}
