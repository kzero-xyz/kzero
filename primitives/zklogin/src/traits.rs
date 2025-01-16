use scale_info::TypeInfo;
use sp_runtime::{
    generic::{CheckedExtrinsic, UncheckedExtrinsic},
    traits::{Extrinsic, SignaturePayload, SignedExtension},
};

/// The extension for trait `Extrinsic` to provide functions for zklogin.
pub trait ExtrinsicExt: Extrinsic
where
    <Self as Extrinsic>::SignaturePayload: SignaturePayloadExt,
{
    fn signature_payload(&self) -> Option<&Self::SignaturePayload>;
}

impl<Address: TypeInfo, Call: TypeInfo, Signature: TypeInfo, Extra: SignedExtension + TypeInfo>
    ExtrinsicExt for UncheckedExtrinsic<Address, Call, Signature, Extra>
{
    fn signature_payload(&self) -> Option<&Self::SignaturePayload> {
        self.signature.as_ref()
    }
}

/// The extension for trait `SignaturePayload` to provide functions for zklogin.
pub trait SignaturePayloadExt: SignaturePayload {
    fn signature_address(&self) -> &Self::SignatureAddress;
}

type UncheckedSignaturePayload<Address, Signature, Extra> = (Address, Signature, Extra);
impl<Address: TypeInfo, Signature: TypeInfo, Extra: TypeInfo> SignaturePayloadExt
    for UncheckedSignaturePayload<Address, Signature, Extra>
{
    fn signature_address(&self) -> &Self::SignatureAddress {
        &self.0
    }
}

#[cfg(feature = "std")]
type TxSignaturePayload<Extra> = (u64, Extra);
#[cfg(feature = "std")]
impl<Extra: TypeInfo> SignaturePayloadExt for TxSignaturePayload<Extra> {
    fn signature_address(&self) -> &Self::SignatureAddress {
        &self.0
    }
}

pub trait ReplaceSender {
    type AccountId;

    fn replace_sender(&mut self, sender: Self::AccountId);
}

impl<AccountId, Call, Extra> ReplaceSender for CheckedExtrinsic<AccountId, Call, Extra> {
    type AccountId = AccountId;

    fn replace_sender(&mut self, sender: Self::AccountId) {
        match &mut self.signed {
            Some((account_id, _)) => {
                *account_id = sender;
            }
            None => { /* do nothing */ }
        }
    }
}
