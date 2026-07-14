# Security Specification for IP Camera Hub v4 WebRTC

This specification outlines the data invariants, validation schema rules, and penetration test cases for the WebRTC signaling collection stored in Firestore.

## 1. Data Invariants

1. **Viewer Session Lifecycle**: A session must transition through `request_offer` -> `offer_sent` -> `answer_sent` -> `closed`. State shortcuts or invalid states are forbidden.
2. **Identity Boundaries**: A viewer can only create or update their own session (`viewerId` matching the request's viewer context).
3. **Volumetric Boundaries**: SDP fields and ICE candidate strings are strictly bounded to prevent memory depletion or resource exhaust.
4. **Relational Sync**: ICE candidates must belong to an active, valid viewer session.

## 2. Dirty Dozen payloads

The following payloads violate the safety invariants and must be blocked by `firestore.rules`:

1. **Identity Spoofing**: Viewer creating a session claiming a different viewerId.
2. **State Shortcutting**: Creating a session directly in `answer_sent` state.
3. **Shadow Field Injection**: Writing undocumented field keys like `isAdmin: true` inside a ViewerSession.
4. **Invalid State String**: Setting `state` to an arbitrary string like `malicious_state`.
5. **Payload Size Flood**: Writing massive SDP block (over 64KB) to trigger Denial of Wallet.
6. **Path ID Poisoning**: Using a malicious non-alphanumeric document ID like `/streams/invalid$$$ID/viewers/v123`.
7. **ICE Candidate Spoofing**: Viewer writing an ICE candidate claiming the sender is `'broadcaster'`.
8. **Invalid Candidate Structure**: Omitting the candidate payload inside `IceCandidate`.
9. **Timestamp Spoofing**: Providing a client-side timestamp that is in the future instead of server-time.
10. **State Mutation Lockout**: Mutating the `createdAt` timestamp of an existing session.
11. **Anonymity Violations**: Unauthorized reads of another viewer's session data.
12. **Broadcaster Spoofing**: Modifying an answer when acting as the broadcaster.
