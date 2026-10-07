// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Registry ownership, expiry, canonical framing and bounded transition regressions.

use contract_sdk::registry::{
    self, Lease, RegistryAction as Action, RegistryCall as Call, RegistryError as Error,
    RegistryRecord as Record,
};

fn apply(
    name: &[u8],
    action: Action<'_>,
    previous: Option<&[u8]>,
    caller: u8,
    height: u64,
) -> Result<Option<Vec<u8>>, Error> {
    let call = Call { name, action };
    let mut encoded = [0; registry::MAX_CALL];
    let length = call.encode(&mut encoded)?;
    assert_eq!(Call::decode(&encoded[..length])?, call);
    let mut output = [0; registry::MAX_LEASE];
    registry::transition(call, previous, [caller; 32], height, &mut output)
        .map(|length| length.map(|length| output[..length].to_vec()))
}

#[test]
fn registry_requires_live_ownership_for_every_mutation_and_prevents_confusable_takeover() {
    let record = Record {
        kind: 0,
        value: &[9; 32],
    };
    let first = apply(b"alice", Action::Register(10, record), None, 1, 5)
        .unwrap()
        .unwrap();
    let lease = Lease::decode(&first).unwrap();
    assert_eq!((lease.issued, lease.expires, lease.owner), (5, 15, [1; 32]));
    for name in [b"alice".as_slice(), b"a1ice"] {
        assert_eq!(
            apply(name, Action::Register(10, record), Some(&first), 2, 14),
            Err(Error::Occupied)
        );
    }
    for action in [
        Action::Update(record),
        Action::Renew(10),
        Action::Release,
        Action::Transfer([2; 32]),
    ] {
        assert_eq!(
            apply(b"alice", action, Some(&first), 2, 10),
            Err(Error::Owner)
        );
        assert_eq!(
            apply(b"a1ice", action, Some(&first), 1, 10),
            Err(Error::Expired)
        );
        assert_eq!(
            apply(b"alice", action, Some(&first), 1, 15),
            Err(Error::Expired)
        );
    }
    let renewed = apply(b"alice", Action::Renew(10), Some(&first), 1, 10)
        .unwrap()
        .unwrap();
    assert_eq!(Lease::decode(&renewed).unwrap().expires, 25);
    let transferred = apply(b"alice", Action::Transfer([2; 32]), Some(&renewed), 1, 10)
        .unwrap()
        .unwrap();
    assert_eq!(
        apply(b"alice", Action::Release, Some(&transferred), 1, 10),
        Err(Error::Owner)
    );
    let updated = apply(
        b"alice",
        Action::Update(Record {
            kind: 1,
            value: b"https://service.internal",
        }),
        Some(&transferred),
        2,
        10,
    )
    .unwrap()
    .unwrap();
    assert_eq!(Lease::decode(&updated).unwrap().record.kind, 1);
    assert_eq!(
        apply(b"alice", Action::Release, Some(&updated), 2, 10).unwrap(),
        None
    );
    let reclaimed = apply(b"a1ice", Action::Register(10, record), Some(&first), 2, 15)
        .unwrap()
        .unwrap();
    assert_eq!(Lease::decode(&reclaimed).unwrap().owner, [2; 32]);
    assert_eq!(
        apply(
            b"alice",
            Action::Renew(registry::MAX_DURATION),
            Some(&first),
            1,
            10
        ),
        Err(Error::Duration)
    );
    for duration in [0, registry::MAX_DURATION + 1, u64::MAX] {
        assert_eq!(
            apply(b"alice", Action::Register(duration, record), None, 1, 5),
            Err(Error::Duration)
        );
    }
    assert_eq!(
        apply(b"alice", Action::Register(5, record), None, 1, u64::MAX - 1),
        Err(Error::Duration)
    );
    assert_eq!(
        apply(b"alice", Action::Transfer([0; 32]), Some(&first), 1, 5),
        Err(Error::Owner)
    );
}

#[test]
fn canonical_inputs_are_bounded_and_never_accept_truncations_or_reserved_names() {
    for name in [
        b"root".as_slice(),
        b"r00t",
        b"a.b",
        b"-alice",
        b"alice-",
        b"A",
        b"a b",
        b"a\0b",
        b"",
        &[b'a'; 64],
    ] {
        assert_eq!(registry::validate_name(name), Err(Error::Name));
    }
    let mut first = [0; registry::MAX_NAME + 7];
    let mut other = first;
    let length = registry::registry_key(b"alice", &mut first).unwrap();
    assert_eq!(
        registry::registry_key(b"a1ice", &mut other).unwrap(),
        length
    );
    assert_eq!(first, other);
    let name = [b'a'; registry::MAX_NAME];
    let value = [b'x'; registry::MAX_RECORD];
    let call = Call {
        name: &name,
        action: Action::Register(
            10,
            Record {
                kind: 1,
                value: &value,
            },
        ),
    };
    let mut input = [0; registry::MAX_CALL];
    assert_eq!(call.encode(&mut input).unwrap(), input.len());
    assert_eq!(Call::decode(&input).unwrap(), call);
    let mut output = [0; registry::MAX_LEASE];
    assert_eq!(
        registry::transition(call, None, [1; 32], 1, &mut output).unwrap(),
        Some(output.len())
    );
    assert_eq!(Lease::decode(&output).unwrap().record.value, value);
    for length in 0..input.len() {
        assert!(Call::decode(&input[..length]).is_err());
    }
    for length in 0..output.len() {
        assert!(Lease::decode(&output[..length]).is_err());
    }
    assert!(Call::decode(&[input.as_slice(), &[0]].concat()).is_err());
    assert!(Lease::decode(&[output.as_slice(), &[0]].concat()).is_err());
}
