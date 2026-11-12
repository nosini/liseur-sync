# ADR-F001: Readers manage their own KOReader mirror

- **Status:** Accepted
- **Date:** 2026-11-12
- **Amends:** [ADR-0047](0047-mirroring-reading-to-a-koreader-peer.md),
  [ADR-0061](0061-several-mirrors.md)

## Context

Every mirror so far is the operator's: a `[mirror]` or `[[mirrors]]`
entry in the configuration file, saved from an administration page and
applied by a restart. A reader who wants their position kept in step
with their own KOReader sync server, or with a Calibre-Web they run, has
to ask an administrator to put their peer credential into the server's
configuration.

This fork shipped a version of this before ADR-0061 existed (its own
ADR-0053, a number upstream has since used for something else). It
allowed one sealed mirror per account, replaced the operator's mirror
for an account once its owner saved one, and recorded its table as
schema version 20, the slot upstream later gave to `furthestFloor`.
Deployed databases hold those rows. A later build renamed the table to
`fork_user_mirrors`, gave the version back to upstream and left the rows
alone, without running them.

Three things are different about a mirror a reader configures:

- **Its credential cannot be hashed.** It is presented to a peer on
  every request. ADR-0047 kept the operator's in configuration for that
  reason; a reader's has nowhere to go but the database.
- **Its address is chosen by somebody who is not the operator.** An
  operator's entry may point anywhere, because the operator decides what
  the server reaches. A reader's address would otherwise let any account
  make the server request a URL on the network it runs on.
- **It changes while the server runs.** A reader cannot restart the
  server, and asking them to wait for one would not be a feature.

## Decision

**Each account may save one KOReader-sync mirror of its own from
Settings → Devices & integrations → Mirror. It runs beside the
operator's mirrors and replaces none of them. Its settings are sealed
with a key kept outside the database, its peer must be on a public
address unless the operator allows the origin, it is applied without a
restart, and no two accounts — whether through a personal mirror or a
configured one — ever mirror into one remote account.**

- **Storage.** One row per account in `fork_user_mirrors`:
  `(user_id, sealed_config, target_hash)`, deleted with the account.
  `sealed_config` is AES-256-GCM over the JSON of
  `config.MirrorConfig`, with `mirror-v1:<user id>` as associated data
  so a row copied to another account does not open. This is the fork's
  format, so its rows open unchanged. The 32-byte key lives in
  `mirror_key_file`, by default `mirror.key` beside the SQLite database
  or beside the cache directory for PostgreSQL. It is created on the
  first save with mode `0600`, refused if anybody else can read it, and
  once any row exists, a missing key is an error rather than a new key.
  Encryption with a key a database dump does not contain is the closest
  this server can come to the rule that secrets are stored hashed, and
  the key must be backed up with the database.
- **Schema.** The table is created by the fork's own migration ledger,
  `fork_migrations`, not by `schema_migrations`: the fork never takes an
  upstream version number again. Ledger migrations run after upstream's
  in the same transaction. Fork tables carry a `fork_` prefix, so a
  table upstream adds later cannot collide with one. The rename of a
  fork database's `user_mirrors` table now runs only on a database
  without the ledger, so a `user_mirrors` table upstream might add one
  day is never mistaken for the fork's.
- **What a reader chooses.** A peer URL, a remote username, and either
  the KOReader key (the form takes the password and stores its MD5) or,
  for Calibre-Web, the password itself over HTTP Basic. The protocol is
  always KOReader sync, never BookOrbit, whose credential opens a whole
  account. The intervals are the defaults. The local account comes
  from the row's key, never from the sealed settings, and the worker
  resolves it by ID. A blank password keeps the saved credential only
  while the URL, the remote user and the authentication method stay the
  same, so a changed address never receives the previous peer's
  password. An enabled save signs in to the peer before anything is
  written.
- **Name and device.** Every personal mirror runs under the name
  `personal_mirror`. The name keys cursors per account and prefixes the
  device a pulled position is filed under. A `[[mirrors]]` name cannot
  contain an underscore, and the single `[mirror]` entry is refused this
  name, so a personal mirror never shares bookkeeping with an operator's
  entry for the same account. A fork row's own name is ignored, so its
  cursors start over once. That costs one redundant exchange per book.
  The device written to the peer is `liseur-sync-<user id>` unless the
  saved settings already name one.
- **Address restrictions.** The worker and the save's connection test
  use a transport that resolves the host at dial time, refuses the
  connection if any resolved address is private, loopback, link-local,
  shared or reserved, and dials the address it checked. It uses no
  environment proxy. An origin listed in `mirror_allowed_origins`
  (scheme, host and port) is exempt, so an operator can allow a peer on
  the LAN. Redirects stay refused, as for every mirror.
- **One remote account, one mirror.** ADR-0061's rule extends across
  users. `target_hash` is an HMAC, under a subkey of the vault key, of
  `config.MirrorTargetKey`, the same folding the configuration's
  duplicate check uses. A `UNIQUE` index on it makes the database refuse
  the second account, with no read-then-write race. A disabled mirror
  holds no hash. An enabled operator entry takes precedence: a personal
  save into its remote account is refused, and a personal row that
  matches one after a configuration change does not run, and its owner
  sees why. A row without a hash (the fork's) is filled in when the
  manager opens it, and only if the row is unchanged since it was
  read. A row whose target another account already holds does not run
  and is retried until that account lets go.
- **Live reload.** One manager follows the rows. It re-reads them when
  a save or a removal tells it to and every 15 seconds otherwise. A row
  whose sealed settings changed gets a new worker, and the manager
  cancels the old worker and waits for it to return before starting the
  new one. That join is what ADR-0061 lacked for configuration entries.
  Those still need a restart: their source is a file that several
  processes and editors may write, while a row changes only through one
  handler in this process.
- **What an administrator sees.** On an account's administration page:
  whether it has a personal mirror, the peer's host, and whether it is
  on. Never the remote user, the path or the credential.

## Consequences

- A reader's peer credential is in the database, encrypted. Whoever has
  both the database and the key file has every reader's peer credential.
  The deployment guide says to back the key up, and to keep that copy
  apart from the database backups, because the two together reveal the
  credentials.
- A disabled personal mirror no longer suppresses an operator's mirror
  for the same account, as the fork's did. An operator entry and a
  personal one for the same account run side by side, as two configured
  entries do (ADR-0061), as long as their remote accounts differ.
- A peer on a private network needs the operator's permission. A reader
  who self-hosts KOReader sync behind the same router as this server has
  to ask for `mirror_allowed_origins`.
- Losing the key makes every saved personal mirror unreadable. Each
  reader sees that on the page, and the operator sees it in the log.
  Each reader can remove the mirror and save it again.

## Acceptance criteria

- A database that ran the fork, one that only had its table renamed,
  and a fresh one all end with the same table and one ledger row, and
  restart cleanly. The fork's sealed rows open.
- A reader can save, change, turn off and remove a mirror, and each
  change takes effect without a restart.
- No page renders a credential. A reader can neither read nor change
  another account's mirror. Every write needs the CSRF token.
- A second account mirroring into one remote account, or a personal
  mirror into an operator entry's remote account, is refused.
- A private peer is never dialled unless its origin is allowed.
