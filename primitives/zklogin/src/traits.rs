use sp_core::crypto::AccountId32;

use sp_runtime::MultiAddress;

use crate::EphPubKey;

#[derive(Debug)]
pub enum EphPubkeyErr {
    /// Invalid pubkey.
    Invalid,
    /// Pubkey can not more than 32 bytes.
    InvalidLength,
    /// Pubkey can not be empty.
    Empty,
}

///
pub trait TryIntoEphPubKey {
    // Required method
    fn try_into_eph_key(&self) -> Result<EphPubKey, EphPubkeyErr>;
}

fn extend_to_eph_pubkey(source: &[u8]) -> Result<EphPubKey, EphPubkeyErr> {
    let source_len = source.len();
    let mut pubkey: EphPubKey = Default::default();
    let len = pubkey.len();
    if source_len == 0 {
        return Err(EphPubkeyErr::Empty);
    }
    if source_len > len {
        return Err(EphPubkeyErr::InvalidLength);
    }
    // `source_len` <= `len`
    pubkey[0..source_len].copy_from_slice(source);
    Ok(pubkey)
}

impl<AccountId: AsRef<[u8]>, AccountIndex> TryIntoEphPubKey
    for MultiAddress<AccountId, AccountIndex>
{
    fn try_into_eph_key(&self) -> Result<EphPubKey, EphPubkeyErr> {
        (&self).try_into_eph_key()
    }
}

impl<AccountId: AsRef<[u8]>, AccountIndex> TryIntoEphPubKey
    for &MultiAddress<AccountId, AccountIndex>
{
    fn try_into_eph_key(&self) -> Result<EphPubKey, EphPubkeyErr> {
        match self {
            MultiAddress::Id(account_id) => extend_to_eph_pubkey(account_id.as_ref()),
            MultiAddress::Index(_index) => Err(EphPubkeyErr::Invalid),
            MultiAddress::Raw(raw) => extend_to_eph_pubkey(raw.as_ref()),
            MultiAddress::Address32(bytes32) => extend_to_eph_pubkey(bytes32.as_ref()),
            MultiAddress::Address20(bytes20) => extend_to_eph_pubkey(bytes20.as_ref()),
        }
    }
}

impl TryIntoEphPubKey for AccountId32 {
    fn try_into_eph_key(&self) -> Result<EphPubKey, EphPubkeyErr> {
        Ok(*self.as_ref())
    }
}

impl TryIntoEphPubKey for [u8; 20] {
    fn try_into_eph_key(&self) -> Result<EphPubKey, EphPubkeyErr> {
        extend_to_eph_pubkey(self.as_ref())
    }
}
