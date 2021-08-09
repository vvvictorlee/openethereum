// Copyright 2015-2020 Parity Technologies (UK) Ltd.
// This file is part of OpenEthereum.

// OpenEthereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// OpenEthereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with OpenEthereum.  If not, see <http://www.gnu.org/licenses/>.

//! Utils implement

use engines::{
    congress::{ADDRESS_LENGTH, SIGNATURE_LENGTH, VANITY_LENGTH},
    EngineError,
};
use error::Error;
use ethereum_types::{Address, H256,H160};
use crypto::publickey::{self, Signature};
use lru_cache::LruCache;
use parking_lot::RwLock;
use std::{
    collections::{BTreeSet, HashSet},
    str::FromStr,
};
use types::{
    header::Header,
    transaction::{Action, SignedTransaction},
};

/// How many recovered signature to cache in the memory.
const CREATOR_CACHE_NUM: usize = 4096;
lazy_static! {
    /// key: header hash
    /// value: creator address
    static ref CREATOR_BY_HASH: RwLock<LruCache<H256, Address>> = RwLock::new(LruCache::new(CREATOR_CACHE_NUM));

    pub static ref VALIDATOR_CONTRACT: Address =  Address::from_str("000000000000000000000000000000000000f000").unwrap();
    pub static ref PUNISH_CONTRACT: Address =  Address::from_str("000000000000000000000000000000000000f001").unwrap();
    pub static ref PROPOSAL_CONTRACT: Address = Address::from_str("000000000000000000000000000000000000f002").unwrap();
    pub static ref SYSTEM_CONTRACTS: HashSet<Address> = [
        "000000000000000000000000000000000000f000",
        "000000000000000000000000000000000000f001",
        "000000000000000000000000000000000000f002",
    ]
    .iter()
    .map(|x| Address::from_str(x).unwrap())
    .collect();
}

/// whether the contract is system or not
pub fn is_to_system_contract(addr: &Address) -> bool {
    SYSTEM_CONTRACTS.contains(addr)
}

/// whether the transaction is system or not
pub fn is_system_transaction(tx: &SignedTransaction, author: &Address) -> bool {
    if let Action::Call(to) = tx.as_unsigned().tx().action {
        tx.sender().eq(author) && is_to_system_contract(&to) && tx.as_unsigned().tx().gas_price == 0.into()
    } else {
        false
    }
}

/// Recover block creator from signature
pub fn recover_creator(header: &Header) -> Result<Address, Error> {
    // Initialization
    let mut cache = CREATOR_BY_HASH.write();

    if let Some(creator) = cache.get_mut(&header.hash()) {
        return Ok(*creator);
    }

    let data = header.extra_data();

    if data.len() < VANITY_LENGTH + SIGNATURE_LENGTH {
        Err(EngineError::CongressMissingSignature)?
    }

    // Split `signed_extra data` and `signature`
    let (signed_data_slice, signature_slice) = data.split_at(data.len() - SIGNATURE_LENGTH);

    // convert `&[u8]` to `[u8; 65]`
    let signature = {
        let mut s = [0; SIGNATURE_LENGTH];
        s.copy_from_slice(signature_slice);
        s
    };

    // modify header and hash it
    let unsigned_header = &mut header.clone();
    unsigned_header.set_extra_data(signed_data_slice.to_vec());
    let msg = unsigned_header.hash();

    let pubkey = publickey::recover(&Signature::from(signature), &msg)?;
    let creator = publickey::public_to_address(&pubkey);

    cache.insert(header.hash(), creator.clone());
    Ok(creator)
}

/// Extract validator list from extra_data.
///
/// Layout of extra_data:
/// ----
/// VANITY: 32 bytes
/// Validators: N * 20 bytes as hex encoded (20 characters)
/// Signature: 65 bytes
/// --
pub fn extract_validators(header: &Header) -> Result<BTreeSet<Address>, Error> {
    let data = header.extra_data();

    if data.len() <= VANITY_LENGTH + SIGNATURE_LENGTH {
        Err(EngineError::CongressMissingSignature)?
    }

    // extract only the portion of extra_data which includes the signer list
    let validators_raw = &data[(VANITY_LENGTH)..data.len() - (SIGNATURE_LENGTH)];

    if validators_raw.len() % ADDRESS_LENGTH != 0 {
        Err(EngineError::CongressCheckpointInvalidValidators(
            validators_raw.len(),
        ))?
    }

    let num_validators = validators_raw.len() / 20;

    let validators: BTreeSet<Address> = (0..num_validators)
        .map(|i| {
            let start = i * ADDRESS_LENGTH;
            let end = start + ADDRESS_LENGTH;
            H160::from_slice(&validators_raw[start..end])
        })
        .collect();

    Ok(validators)
}
