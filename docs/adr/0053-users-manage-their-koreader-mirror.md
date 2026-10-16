# ADR-0053: Users manage their KOReader mirror

- Status: Accepted
- Amends: [ADR-0047](0047-mirroring-reading-to-a-koreader-peer.md)

## Context

The outbound mirror already scopes every position and cursor to one account,
but configuring it requires an administrator to collect the reader's peer
credential and restart the server. Each reader should be able to connect and
disconnect their own peer from the web settings.

## Decision

Each account may save one personal KOReader sync mirror under Settings →
Devices & integrations. Its local account is always the signed-in user;
submitted account IDs, protocol names and device IDs confer no authority.
The UI supports standard KOReader authentication (an MD5-derived key) and
HTTP Basic authentication (the peer password, for Calibre-Web). A blank
password preserves the credential only for the same URL, username and
authentication method. An enabled save tests the connection first.

`user_mirrors` stores an encrypted configuration keyed by `user_id`, with a
foreign key that cascades when the user is removed. AES-256-GCM authenticates
the account ID as associated data and uses a random nonce on every save.
The 32-byte encryption key lives outside the database, in `mirror_key_file`,
created atomically with mode 0600 on the first save. The default is
`mirror.key` beside the SQLite database, or beside the cover cache directory
for PostgreSQL. Backups must include this file. A missing key when settings
already exist is an error, never an invitation to generate a replacement.
This explicitly replaces ADR-0047's decision to defer encrypted multi-account
credential storage. These are credentials the server presents, not login
verifiers; hashing them again would make them unusable.

One manager reads the encrypted configurations at startup, after a UI save
and on a two-second safety timer. It cancels and joins a replaced worker
before starting its replacement. Workers bind to immutable user IDs and
recheck account enablement before every pass. Existing operator-configured
mirrors remain available, including BookOrbit, until that account saves
personal settings. Even disabled personal settings suppress the operator
mirror. No migration copies a plaintext credential out of TOML.

User-selected peers introduce a new outbound trust boundary. Their HTTP
transport resolves at dial time, refuses private and reserved addresses,
and dials a checked IP directly. It uses no environment proxy and follows
no redirects. An operator can allow an exact private origin using
`mirror_allowed_origins`; this does not waive the HTTPS requirement.
The same transport applies to connection tests and running workers.
Peer errors redact known credentials before they are logged or stored.

## Consequences

Readers configure their own peer without an administrator or a restart.
They never see other accounts' peer settings, and no response returns a
saved secret. The encryption key is now persistent deployment data. Losing
it requires restoring the original key; a database backup alone cannot
recover personal mirrors. Operators still decide which private services
users may contact. The position exchange protocol, timestamp policy,
cursor isolation, reset refusal and echo detection are unchanged.

The schema change is additive: migration 20 on SQLite, 19 on PostgreSQL.
Upgrades preserve existing catalogs, reading graphs and mirror cursors.
