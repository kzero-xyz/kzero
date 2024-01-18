pub type ZkAuthResult<T> = Result<T, ZkAuthError>;
use ark_relations::r1cs::SynthesisError;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ZkAuthError {
    /// Circom error
    FqParseError,

    /// Invalid value was given to the function
    InvalidInput,

    /// Input length is wrong.
    InputLengthWrong(usize),

    /// JWK not found
    JWKNotFound,

    /// Modulus base64 decode error
    ModulusDecodeError,

    /// Groth16 Proof verification fails
    ProofVerifyingFailed,

    /// General cryptographic error.
    GeneralError(SynthesisError),
}

impl From<SynthesisError> for ZkAuthError {
    fn from(value: SynthesisError) -> Self {
        Self::GeneralError(value)
    }
}
