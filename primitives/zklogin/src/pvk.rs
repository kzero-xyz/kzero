use crate::circom::{g1_affine_from_str_projective, g2_affine_from_str_projective};
use ark_bn254::Bn254;
use ark_groth16::{PreparedVerifyingKey, VerifyingKey};

mod prod {
    use crate::circom::{StrCircomG1, StrCircomG2};

    pub const VK_ALPHA_1: StrCircomG1 = [
        "21529901943976716921335152104180790524318946701278905588288070441048877064089",
        "7775817982019986089115946956794180159548389285968353014325286374017358010641",
        "1",
    ];

    pub const VK_BETA_2: StrCircomG2 = [
        [
            "6600437987682835329040464538375790690815756241121776438004683031791078085074",
            "16207344858883952201936462217289725998755030546200154201671892670464461194903",
        ],
        [
            "17943105074568074607580970189766801116106680981075272363121544016828311544390",
            "18339640667362802607939727433487930605412455701857832124655129852540230493587",
        ],
        ["1", "0"],
    ];

    pub const VK_GAMMA_2: StrCircomG2 = [
        [
            "10857046999023057135944570762232829481370756359578518086990519993285655852781",
            "11559732032986387107991004021392285783925812861821192530917403151452391805634",
        ],
        [
            "8495653923123431417604973247489272438418190587263600148770280649306958101930",
            "4082367875863433681332203403145435568316851327593401208105741076214120093531",
        ],
        ["1", "0"],
    ];

    pub const VK_DELTA_2: StrCircomG2 = [
        [
            "19260309516619721648285279557078789954438346514188902804737557357941293711874",
            "2480422554560175324649200374556411861037961022026590718777465211464278308900",
        ],
        [
            "14489104692423540990601374549557603533921811847080812036788172274404299703364",
            "12564378633583954025611992187142343628816140907276948128970903673042690269191",
        ],
        ["1", "0"],
    ];

    pub const E: [StrCircomG1; 2] = [
        [
            "1607694606386445293170795095076356565829000940041894770459712091642365695804",
            "18066827569413962196795937356879694709963206118612267170825707780758040578649",
            "1",
        ],
        [
            "20653794344898475822834426774542692225449366952113790098812854265588083247207",
            "3296759704176575765409730962060698204792513807296274014163938591826372646699",
            "1",
        ],
    ];
}

mod test {
    use crate::circom::{StrCircomG1, StrCircomG2};
    pub const VK_ALPHA_1: StrCircomG1 = [
        "21529901943976716921335152104180790524318946701278905588288070441048877064089",
        "7775817982019986089115946956794180159548389285968353014325286374017358010641",
        "1",
    ];

    pub const VK_BETA_2: StrCircomG2 = [
        [
            "6600437987682835329040464538375790690815756241121776438004683031791078085074",
            "16207344858883952201936462217289725998755030546200154201671892670464461194903",
        ],
        [
            "17943105074568074607580970189766801116106680981075272363121544016828311544390",
            "18339640667362802607939727433487930605412455701857832124655129852540230493587",
        ],
        ["1", "0"],
    ];

    pub const VK_GAMMA_2: StrCircomG2 = [
        [
            "10857046999023057135944570762232829481370756359578518086990519993285655852781",
            "11559732032986387107991004021392285783925812861821192530917403151452391805634",
        ],
        [
            "8495653923123431417604973247489272438418190587263600148770280649306958101930",
            "4082367875863433681332203403145435568316851327593401208105741076214120093531",
        ],
        ["1", "0"],
    ];

    pub const VK_DELTA_2: StrCircomG2 = [
        [
            "19260309516619721648285279557078789954438346514188902804737557357941293711874",
            "2480422554560175324649200374556411861037961022026590718777465211464278308900",
        ],
        [
            "14489104692423540990601374549557603533921811847080812036788172274404299703364",
            "12564378633583954025611992187142343628816140907276948128970903673042690269191",
        ],
        ["1", "0"],
    ];

    pub const E: [StrCircomG1; 2] = [
        [
            "1607694606386445293170795095076356565829000940041894770459712091642365695804",
            "18066827569413962196795937356879694709963206118612267170825707780758040578649",
            "1",
        ],
        [
            "20653794344898475822834426774542692225449366952113790098812854265588083247207",
            "3296759704176575765409730962060698204792513807296274014163938591826372646699",
            "1",
        ],
    ];
}

/// The prepared verifying key for production env.
pub(crate) fn prod_pvk() -> PreparedVerifyingKey<Bn254> {
    // Convert the Circom G1/G2/GT to arkworks G1/G2/GT
    let vk_alpha_1 = g1_affine_from_str_projective(&prod::VK_ALPHA_1).unwrap();
    let vk_beta_2 = g2_affine_from_str_projective(&prod::VK_BETA_2).unwrap();
    let vk_gamma_2 = g2_affine_from_str_projective(&prod::VK_GAMMA_2).unwrap();
    let vk_delta_2 = g2_affine_from_str_projective(&prod::VK_DELTA_2).unwrap();

    // Create a vector of G1Affine elements from the IC
    let vk_gamma_abc_g1 =
        prod::E.iter().map(|e| g1_affine_from_str_projective(e).unwrap()).collect();

    let vk = VerifyingKey {
        alpha_g1: vk_alpha_1,
        beta_g2: vk_beta_2,
        gamma_g2: vk_gamma_2,
        delta_g2: vk_delta_2,
        gamma_abc_g1: vk_gamma_abc_g1,
    };

    // Convert the verifying key into the prepared form.
    PreparedVerifyingKey::from(vk)
}

/// The prepared verifying key for testing.
pub(crate) fn test_pvk() -> PreparedVerifyingKey<Bn254> {
    // Convert the Circom G1/G2/GT to arkworks G1/G2/GT
    let vk_alpha_1 = g1_affine_from_str_projective(&test::VK_ALPHA_1).unwrap();
    let vk_beta_2 = g2_affine_from_str_projective(&test::VK_BETA_2).unwrap();
    let vk_gamma_2 = g2_affine_from_str_projective(&test::VK_GAMMA_2).unwrap();
    let vk_delta_2 = g2_affine_from_str_projective(&test::VK_DELTA_2).unwrap();

    // Create a vector of G1Affine elements from the IC
    let vk_gamma_abc_g1 =
        test::E.iter().map(|e| g1_affine_from_str_projective(e).unwrap()).collect();

    let vk = VerifyingKey {
        alpha_g1: vk_alpha_1,
        beta_g2: vk_beta_2,
        gamma_g2: vk_gamma_2,
        delta_g2: vk_delta_2,
        gamma_abc_g1: vk_gamma_abc_g1,
    };

    // Convert the verifying key into the prepared form.
    PreparedVerifyingKey::from(vk)
}
