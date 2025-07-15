## Overview

Pallet ZkLogin is a Substrate-based blockchain pallet that enables Web3 applications to authenticate users using traditional OAuth providers (Google, Facebook, Apple, etc.) through zero-knowledge proof verification. This eliminates the need for users to manage private keys while maintaining blockchain security and privacy.

### Key Features
- **OAuth Integration**: Support for major OAuth providers (Google, Facebook, Apple, Twitch, Kakao, Slack, GitHub)
- **Zero-Knowledge Proofs**: Cryptographic verification without revealing user identity
- **Offchain Worker**: Automated JWK (JSON Web Key) management
- **Ephemeral Key Management**: Time-based key expiration for enhanced security
- **On-chain Verification**: ZK proofs are verified directly on the blockchain
- **Flexible Transaction Support**: Enables individualized transactions for various use cases

## Running Tests
```bash
# Run all tests
cd frame/zklogin

cargo test

# Run specific test
cargo test validate_unsigned_should_work
```

After successfully running the test, you should get the following result:
```bash
running 16 tests
test tests::test_parse_jwk_missing_required_fields ... ok
test tests::test_check_jwk_not_onchain_when_different_content ... ok
test tests::test_check_jwk_not_onchain_when_not_exists ... ok
test tests::test_check_jwk_not_onchain_when_same_content ... ok
test tests::test_parse_jwk_success ... ok
test tests::test_parse_jwk_with_google_format ... ok
test tests::__construct_runtime_integrity_test::runtime_integrity_tests ... ok
test tests::test_genesis_config_builds ... ok
test tests::test_fetch_jwks ... ok
test tests::test_update_keys ... ok
test tests::test_submit_jwks_unsigned ... ok
test tests::test_set_jwk ... ok
test tests::validate_unsigned_should_fail_when_jwk_not_match ... ok
test tests::basic_setup_works ... ok
test tests::test_submit_zklogin_unsigned ... ok
test tests::validate_unsigned_should_work ... ok

test result: ok. 16 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 29.16s

   Doc-tests pallet_zklogin
```

To find more about pallet-zklogin, please reach to our [pallet-zklogin document]()
