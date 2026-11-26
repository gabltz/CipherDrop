//! Optional SQLite persistence for explicitly persistent shares and API tokens.
//!
//! * Only shares created with `storage = "persistent"` by an authorized caller
//!   are written here. The memory store has no code path into this module.
//! * Rows are keyed by `SHA-256(share_id)`, so the database alone does not
//!   reveal working share identifiers. It never contains keys or passwords.
//! * Retrieval counters and revocations run inside `BEGIN IMMEDIATE`
//!   transactions; the connection is also serialized by a mutex.
//! * `PRAGMA secure_delete = ON` overwrites deleted content in database pages.
//!   This is best effort only: SQLite journals, filesystem journals, SSD wear
//!   levelling, snapshots and backups may retain old data.
//!
//! All methods are blocking; call them from `spawn_blocking` in async code.

use std::path::Path;

use cipherdrop_protocol::envelope::DecodedKdf;
use cipherdrop_protocol::url::ShareId;
use cipherdrop_protocol::{KDF_SALT_LEN, NONCE_LEN};
use parking_lot::Mutex;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use std::sync::Arc;

use crate::{
    AccessCheck, Consumed, NewShare, RevokeAuth, Status, StoreError, StoredEnvelope, Verifier,
};

const SCHEMA_VERSION: i64 = 2;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS shares (
    id_hash             BLOB PRIMARY KEY,
    nonce               BLOB NOT NULL,
    ciphertext          BLOB NOT NULL,
    kdf_salt            BLOB,
    kdf_memory_kib      INTEGER,
    kdf_iterations      INTEGER,
    kdf_parallelism     INTEGER,
    created_at          INTEGER NOT NULL,
    expires_at          INTEGER,
    remaining_reads     INTEGER CHECK (remaining_reads IS NULL OR remaining_reads > 0),
    revocation_verifier BLOB NOT NULL,
    access_verifier     BLOB,
    access_failures     INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE INDEX IF NOT EXISTS shares_expires_at ON shares (expires_at) WHERE expires_at IS NOT NULL;

CREATE TABLE IF NOT EXISTS api_tokens (
    id                    TEXT PRIMARY KEY,
    name                  TEXT NOT NULL,
    verifier              BLOB NOT NULL,
    scopes                TEXT NOT NULL,
    created_at            INTEGER NOT NULL,
    expires_at            INTEGER,
    rate_limit_per_minute INTEGER,
    daily_create_quota    INTEGER,
    revoked_at            INTEGER
) STRICT;
";

/// Quotas for the persistent store.
#[derive(Debug, Clone, Copy)]
pub struct PersistentLimits {
    pub max_bytes: u64,
    pub max_shares: u64,
}

/// An API token record (verifier only, never the secret).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredToken {
    pub id: String,
    pub name: String,
    pub verifier: Verifier,
    pub scopes: Vec<String>,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub rate_limit_per_minute: Option<u32>,
    pub daily_create_quota: Option<u32>,
}

/// The SQLite-backed persistent store.
pub struct PersistentStore {
    conn: Mutex<Connection>,
    limits: PersistentLimits,
}

impl core::fmt::Debug for PersistentStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PersistentStore")
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

fn id_hash(id: &ShareId) -> [u8; 32] {
    Sha256::digest(id.as_bytes()).into()
}

fn be(e: rusqlite::Error) -> StoreError {
    // Deliberately drop the underlying message: it could contain SQL values.
    let _ = e;
    StoreError::Backend
}

fn to_i64(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

fn to_u64(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

impl PersistentStore {
    /// Open (or create) the database at `path` with owner-only permissions.
    ///
    /// # Errors
    /// Returns [`StoreError::Backend`] if the database cannot be opened or migrated.
    pub fn open(path: &Path, limits: PersistentLimits) -> Result<Self, StoreError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // Create the file 0600 before SQLite touches it; SQLite gives its
            // journal files the same permissions as the database file.
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .open(path)
                .map_err(|_| StoreError::Backend)?;
        }
        let conn = Connection::open(path).map_err(be)?;
        Self::init(conn, limits)
    }

    /// In-memory SQLite database (tests only).
    ///
    /// # Errors
    /// Returns [`StoreError::Backend`] on failure.
    pub fn open_in_memory(limits: PersistentLimits) -> Result<Self, StoreError> {
        Self::init(Connection::open_in_memory().map_err(be)?, limits)
    }

    fn init(conn: Connection, limits: PersistentLimits) -> Result<Self, StoreError> {
        conn.execute_batch(
            "PRAGMA journal_mode = DELETE;
             PRAGMA synchronous = FULL;
             PRAGMA secure_delete = ON;
             PRAGMA temp_store = MEMORY;
             PRAGMA foreign_keys = ON;",
        )
        .map_err(be)?;
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(be)?;
        conn.execute_batch(SCHEMA).map_err(be)?;
        let v: Option<String> = conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'schema_version'",
                [],
                |r| r.get(0),
            )
            .optional()
            .map_err(be)?;
        match v {
            None => {
                conn.execute(
                    "INSERT INTO meta (key, value) VALUES ('schema_version', ?1)",
                    params![SCHEMA_VERSION.to_string()],
                )
                .map_err(be)?;
            }
            Some(v) if v == SCHEMA_VERSION.to_string() => {}
            Some(v) if v == "1" => {
                // v1 → v2: server-enforced access gate.
                conn.execute_batch(
                    "BEGIN IMMEDIATE;
                     ALTER TABLE shares ADD COLUMN access_verifier BLOB;
                     ALTER TABLE shares ADD COLUMN access_failures INTEGER NOT NULL DEFAULT 0;
                     UPDATE meta SET value = '2' WHERE key = 'schema_version';
                     COMMIT;",
                )
                .map_err(be)?;
            }
            Some(_) => return Err(StoreError::Backend),
        }
        Ok(Self {
            conn: Mutex::new(conn),
            limits,
        })
    }

    /// Insert a persistent share, enforcing quotas transactionally.
    ///
    /// # Errors
    /// [`StoreError::CapacityExhausted`], [`StoreError::Duplicate`] or [`StoreError::Backend`].
    pub fn insert(&self, id: &ShareId, share: &NewShare, now: u64) -> Result<(), StoreError> {
        let mut conn = self.conn.lock();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(be)?;
        tx.execute(
            "DELETE FROM shares WHERE expires_at IS NOT NULL AND expires_at <= ?1",
            params![to_i64(now)],
        )
        .map_err(be)?;
        let (count, bytes): (i64, i64) = tx
            .query_row(
                "SELECT COUNT(*), COALESCE(SUM(length(ciphertext)), 0) FROM shares",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(be)?;
        let new_bytes = to_u64(bytes).saturating_add(share.envelope.ciphertext.len() as u64);
        if to_u64(count) >= self.limits.max_shares || new_bytes > self.limits.max_bytes {
            return Err(StoreError::CapacityExhausted);
        }
        let k = share.envelope.kdf.as_ref();
        let res = tx.execute(
            "INSERT INTO shares (id_hash, nonce, ciphertext, kdf_salt, kdf_memory_kib, kdf_iterations,
                                 kdf_parallelism, created_at, expires_at, remaining_reads, revocation_verifier,
                                 access_verifier)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                &id_hash(id)[..],
                &share.envelope.nonce[..],
                &share.envelope.ciphertext,
                k.map(|k| k.salt.to_vec()),
                k.map(|k| k.memory_kib),
                k.map(|k| k.iterations),
                k.map(|k| k.parallelism),
                to_i64(share.meta.created_at),
                share.meta.expires_at.map(to_i64),
                share.meta.remaining_reads,
                &share.revocation.0[..],
                share.access.map(|v| v.0.to_vec()),
            ],
        );
        match res {
            Ok(_) => {}
            Err(rusqlite::Error::SqliteFailure(e, _))
                if e.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                return Err(StoreError::Duplicate);
            }
            Err(e) => return Err(be(e)),
        }
        tx.commit().map_err(be)
    }

    /// Atomically validate and consume one retrieval.
    ///
    /// # Errors
    /// [`StoreError::Unavailable`] or [`StoreError::Backend`].
    pub fn consume(
        &self,
        id: &ShareId,
        now: u64,
        access: AccessCheck<'_>,
    ) -> Result<Consumed, StoreError> {
        let h = id_hash(id);
        let mut conn = self.conn.lock();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(be)?;
        let row = tx
            .query_row(
                "SELECT nonce, ciphertext, kdf_salt, kdf_memory_kib, kdf_iterations, kdf_parallelism,
                        expires_at, remaining_reads, access_verifier, access_failures
                 FROM shares WHERE id_hash = ?1",
                params![&h[..]],
                |r| {
                    Ok((
                        r.get::<_, Vec<u8>>(0)?,
                        r.get::<_, Vec<u8>>(1)?,
                        r.get::<_, Option<Vec<u8>>>(2)?,
                        r.get::<_, Option<u32>>(3)?,
                        r.get::<_, Option<u32>>(4)?,
                        r.get::<_, Option<u32>>(5)?,
                        r.get::<_, Option<i64>>(6)?,
                        r.get::<_, Option<u32>>(7)?,
                        r.get::<_, Option<Vec<u8>>>(8)?,
                        r.get::<_, u32>(9)?,
                    ))
                },
            )
            .optional()
            .map_err(be)?;
        let Some((nonce, ciphertext, salt, m, t, p, expires_at, remaining, gate, failures)) = row
        else {
            return Err(StoreError::Unavailable);
        };
        let expires_at = expires_at.map(to_u64);
        if expires_at.is_some_and(|e| e <= now) {
            tx.execute("DELETE FROM shares WHERE id_hash = ?1", params![&h[..]])
                .map_err(be)?;
            tx.commit().map_err(be)?;
            return Err(StoreError::Unavailable);
        }
        if let Some(g) = gate {
            let v = Verifier(g.try_into().map_err(|_| StoreError::Backend)?);
            if !access.key.is_some_and(|k| v.verify(k)) {
                let failures = failures.saturating_add(1);
                let destroyed = access.max_failures > 0 && failures >= access.max_failures;
                if destroyed {
                    tx.execute("DELETE FROM shares WHERE id_hash = ?1", params![&h[..]])
                        .map_err(be)?;
                } else {
                    tx.execute(
                        "UPDATE shares SET access_failures = ?2 WHERE id_hash = ?1",
                        params![&h[..], failures],
                    )
                    .map_err(be)?;
                }
                tx.commit().map_err(be)?;
                return Err(StoreError::AccessDenied { destroyed });
            }
        }
        let remaining_after = match remaining {
            None => None,
            Some(n) if n > 1 => {
                tx.execute(
                    "UPDATE shares SET remaining_reads = remaining_reads - 1
                     WHERE id_hash = ?1 AND remaining_reads > 1",
                    params![&h[..]],
                )
                .map_err(be)?;
                Some(n - 1)
            }
            Some(_) => {
                tx.execute("DELETE FROM shares WHERE id_hash = ?1", params![&h[..]])
                    .map_err(be)?;
                Some(0)
            }
        };
        tx.commit().map_err(be)?;
        let envelope = decode_row(nonce, ciphertext, salt, m, t, p)?;
        Ok(Consumed {
            envelope: Arc::new(envelope),
            remaining_reads: remaining_after,
            expires_at,
        })
    }

    /// Non-consuming status.
    ///
    /// # Errors
    /// [`StoreError::Backend`] on database failure.
    pub fn status(&self, id: &ShareId, now: u64) -> Result<Option<Status>, StoreError> {
        let h = id_hash(id);
        let conn = self.conn.lock();
        let row = conn
            .query_row(
                "SELECT expires_at, remaining_reads, kdf_salt, kdf_memory_kib, kdf_iterations,
                        kdf_parallelism, access_verifier IS NOT NULL
                 FROM shares WHERE id_hash = ?1",
                params![&h[..]],
                |r| {
                    Ok((
                        r.get::<_, Option<i64>>(0)?,
                        r.get::<_, Option<u32>>(1)?,
                        r.get::<_, Option<Vec<u8>>>(2)?,
                        r.get::<_, Option<u32>>(3)?,
                        r.get::<_, Option<u32>>(4)?,
                        r.get::<_, Option<u32>>(5)?,
                        r.get::<_, bool>(6)?,
                    ))
                },
            )
            .optional()
            .map_err(be)?;
        let Some((e, r, salt, m, t, p, gated)) = row else {
            return Ok(None);
        };
        let e = e.map(to_u64);
        if e.is_some_and(|x| x <= now) {
            return Ok(None);
        }
        let kdf = decode_row(vec![0; NONCE_LEN], Vec::new(), salt, m, t, p)?.kdf;
        Ok(Some(Status {
            expires_at: e,
            remaining_reads: r,
            password_protected: kdf.is_some(),
            access_protected: gated,
            kdf,
        }))
    }

    /// Revoke (delete) a persistent share.
    ///
    /// # Errors
    /// [`StoreError::Unavailable`], [`StoreError::Forbidden`] or [`StoreError::Backend`].
    pub fn revoke(&self, id: &ShareId, auth: RevokeAuth<'_>, now: u64) -> Result<(), StoreError> {
        let h = id_hash(id);
        let mut conn = self.conn.lock();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(be)?;
        let row = tx
            .query_row(
                "SELECT revocation_verifier, expires_at FROM shares WHERE id_hash = ?1",
                params![&h[..]],
                |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Option<i64>>(1)?)),
            )
            .optional()
            .map_err(be)?;
        let Some((v, exp)) = row else {
            return Err(StoreError::Unavailable);
        };
        let expired = exp.map(to_u64).is_some_and(|e| e <= now);
        let verifier = Verifier(v.try_into().map_err(|_| StoreError::Backend)?);
        if !expired && !auth.allows(&verifier) {
            return Err(StoreError::Forbidden);
        }
        tx.execute("DELETE FROM shares WHERE id_hash = ?1", params![&h[..]])
            .map_err(be)?;
        tx.commit().map_err(be)?;
        if expired {
            Err(StoreError::Unavailable)
        } else {
            Ok(())
        }
    }

    /// Delete expired shares; returns the number removed.
    ///
    /// # Errors
    /// [`StoreError::Backend`] on database failure.
    pub fn purge_expired(&self, now: u64) -> Result<usize, StoreError> {
        self.conn
            .lock()
            .execute(
                "DELETE FROM shares WHERE expires_at IS NOT NULL AND expires_at <= ?1",
                params![to_i64(now)],
            )
            .map_err(be)
    }

    /// `(share_count, ciphertext_bytes)`.
    ///
    /// # Errors
    /// [`StoreError::Backend`] on database failure.
    pub fn usage(&self) -> Result<(u64, u64), StoreError> {
        self.conn
            .lock()
            .query_row(
                "SELECT COUNT(*), COALESCE(SUM(length(ciphertext)), 0) FROM shares",
                [],
                |r| Ok((to_u64(r.get(0)?), to_u64(r.get(1)?))),
            )
            .map_err(be)
    }

    /// Readiness probe.
    #[must_use]
    pub fn healthy(&self) -> bool {
        self.conn
            .lock()
            .query_row("SELECT 1", [], |r| r.get::<_, i64>(0))
            .is_ok()
    }

    // ----- API tokens -----

    /// Insert a new API token record.
    ///
    /// # Errors
    /// [`StoreError::Duplicate`] or [`StoreError::Backend`].
    pub fn insert_token(&self, t: &StoredToken) -> Result<(), StoreError> {
        let res = self.conn.lock().execute(
            "INSERT INTO api_tokens (id, name, verifier, scopes, created_at, expires_at,
                                     rate_limit_per_minute, daily_create_quota)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                t.id,
                t.name,
                &t.verifier.0[..],
                t.scopes.join(" "),
                to_i64(t.created_at),
                t.expires_at.map(to_i64),
                t.rate_limit_per_minute,
                t.daily_create_quota,
            ],
        );
        match res {
            Ok(_) => Ok(()),
            Err(rusqlite::Error::SqliteFailure(e, _))
                if e.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                Err(StoreError::Duplicate)
            }
            Err(e) => Err(be(e)),
        }
    }

    /// All non-revoked tokens.
    ///
    /// # Errors
    /// [`StoreError::Backend`] on database failure.
    pub fn list_tokens(&self) -> Result<Vec<StoredToken>, StoreError> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare(
                "SELECT id, name, verifier, scopes, created_at, expires_at, rate_limit_per_minute,
                        daily_create_quota
                 FROM api_tokens WHERE revoked_at IS NULL ORDER BY created_at",
            )
            .map_err(be)?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, i64>(4)?,
                    r.get::<_, Option<i64>>(5)?,
                    r.get::<_, Option<u32>>(6)?,
                    r.get::<_, Option<u32>>(7)?,
                ))
            })
            .map_err(be)?;
        let mut out = Vec::new();
        for row in rows {
            let (id, name, v, scopes, created, exp, rl, q) = row.map_err(be)?;
            out.push(StoredToken {
                id,
                name,
                verifier: Verifier(v.try_into().map_err(|_| StoreError::Backend)?),
                scopes: scopes.split_whitespace().map(str::to_owned).collect(),
                created_at: to_u64(created),
                expires_at: exp.map(to_u64),
                rate_limit_per_minute: rl,
                daily_create_quota: q,
            });
        }
        Ok(out)
    }

    /// Mark a token revoked. Returns `false` if no active token had that id.
    ///
    /// # Errors
    /// [`StoreError::Backend`] on database failure.
    pub fn revoke_token(&self, id: &str, now: u64) -> Result<bool, StoreError> {
        self.conn
            .lock()
            .execute(
                "UPDATE api_tokens SET revoked_at = ?2, verifier = zeroblob(32)
                 WHERE id = ?1 AND revoked_at IS NULL",
                params![id, to_i64(now)],
            )
            .map(|n| n > 0)
            .map_err(be)
    }
}

fn decode_row(
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    salt: Option<Vec<u8>>,
    m: Option<u32>,
    t: Option<u32>,
    p: Option<u32>,
) -> Result<StoredEnvelope, StoreError> {
    let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| StoreError::Backend)?;
    let kdf = match (salt, m, t, p) {
        (None, None, None, None) => None,
        (Some(s), Some(m), Some(t), Some(p)) => Some(DecodedKdf {
            salt: <[u8; KDF_SALT_LEN]>::try_from(s).map_err(|_| StoreError::Backend)?,
            memory_kib: m,
            iterations: t,
            parallelism: p,
        }),
        _ => return Err(StoreError::Backend),
    };
    Ok(StoredEnvelope {
        nonce,
        ciphertext,
        kdf,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ShareMeta;

    fn id(n: u8) -> ShareId {
        ShareId::from_bytes([n; 16])
    }

    fn share(reads: Option<u32>, exp: Option<u64>, kdf: bool) -> NewShare {
        NewShare {
            envelope: StoredEnvelope {
                nonce: [1; 12],
                ciphertext: vec![2; 64],
                kdf: kdf.then_some(DecodedKdf {
                    salt: [3; 16],
                    memory_kib: 65536,
                    iterations: 3,
                    parallelism: 1,
                }),
            },
            meta: ShareMeta {
                created_at: 1,
                expires_at: exp,
                remaining_reads: reads,
            },
            revocation: Verifier::from_secret(b"rv"),
            access: None,
        }
    }

    fn limits() -> PersistentLimits {
        PersistentLimits {
            max_bytes: 1 << 20,
            max_shares: 100,
        }
    }

    #[test]
    fn persistent_lifecycle_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cd.sqlite3");
        {
            let s = PersistentStore::open(&path, limits()).unwrap();
            s.insert(&id(1), &share(Some(2), None, true), 0).unwrap();
            s.insert(&id(2), &share(None, Some(100), false), 0).unwrap();
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        let s = PersistentStore::open(&path, limits()).unwrap();
        let st = s.status(&id(1), 0).unwrap().unwrap();
        assert!(st.password_protected);
        let c = s.consume(&id(1), 0, AccessCheck::none()).unwrap();
        assert_eq!(c.remaining_reads, Some(1));
        assert_eq!(c.envelope.kdf.unwrap().memory_kib, 65536);
        assert_eq!(
            s.consume(&id(1), 0, AccessCheck::none())
                .unwrap()
                .remaining_reads,
            Some(0)
        );
        assert_eq!(
            s.consume(&id(1), 0, AccessCheck::none()).unwrap_err(),
            StoreError::Unavailable
        );
        assert_eq!(
            s.consume(&id(2), 5, AccessCheck::none())
                .unwrap()
                .remaining_reads,
            None
        );
        assert!(
            s.consume(&id(2), 100, AccessCheck::none()).is_err(),
            "expired"
        );
        assert_eq!(s.usage().unwrap(), (0, 0));
    }

    #[test]
    fn database_does_not_contain_raw_share_ids() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cd.sqlite3");
        let s = PersistentStore::open(&path, limits()).unwrap();
        let marker = ShareId::from_bytes(*b"RAW-ID-MARKER-01");
        s.insert(&marker, &share(Some(1), None, false), 0).unwrap();
        drop(s);
        let bytes = std::fs::read(&path).unwrap();
        assert!(!bytes.windows(16).any(|w| w == b"RAW-ID-MARKER-01"));
    }

    #[test]
    fn access_gate_persists_failures() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("g.sqlite3");
        let wrong = AccessCheck {
            key: Some(b"bad"),
            max_failures: 2,
        };
        {
            let s = PersistentStore::open(&path, limits()).unwrap();
            let mut sh = share(Some(1), None, true);
            sh.access = Some(Verifier::from_secret(b"good"));
            s.insert(&id(5), &sh, 0).unwrap();
            assert!(s.status(&id(5), 0).unwrap().unwrap().access_protected);
            assert_eq!(
                s.consume(&id(5), 0, wrong).unwrap_err(),
                StoreError::AccessDenied { destroyed: false }
            );
        }
        let s = PersistentStore::open(&path, limits()).unwrap();
        assert_eq!(
            s.consume(&id(5), 0, wrong).unwrap_err(),
            StoreError::AccessDenied { destroyed: true }
        );
        assert!(s.status(&id(5), 0).unwrap().is_none());
    }

    #[test]
    fn migrates_v1_schema() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v1.sqlite3");
        {
            let c = Connection::open(&path).unwrap();
            c.execute_batch("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT;
                INSERT INTO meta VALUES ('schema_version', '1');
                CREATE TABLE shares (id_hash BLOB PRIMARY KEY, nonce BLOB NOT NULL, ciphertext BLOB NOT NULL,
                  kdf_salt BLOB, kdf_memory_kib INTEGER, kdf_iterations INTEGER, kdf_parallelism INTEGER,
                  created_at INTEGER NOT NULL, expires_at INTEGER,
                  remaining_reads INTEGER CHECK (remaining_reads IS NULL OR remaining_reads > 0),
                  revocation_verifier BLOB NOT NULL) STRICT;").unwrap();
        }
        let s = PersistentStore::open(&path, limits()).unwrap();
        s.insert(&id(1), &share(Some(1), None, false), 0).unwrap();
        assert!(s.consume(&id(1), 0, AccessCheck::none()).is_ok());
    }

    #[test]
    fn quotas_enforced() {
        let s = PersistentStore::open_in_memory(PersistentLimits {
            max_bytes: 128,
            max_shares: 10,
        })
        .unwrap();
        s.insert(&id(1), &share(Some(1), None, false), 0).unwrap();
        s.insert(&id(2), &share(Some(1), None, false), 0).unwrap();
        assert_eq!(
            s.insert(&id(3), &share(Some(1), None, false), 0),
            Err(StoreError::CapacityExhausted)
        );
        assert_eq!(
            s.insert(&id(1), &share(Some(1), None, false), 0),
            Err(StoreError::CapacityExhausted)
        );
    }

    #[test]
    fn revocation() {
        let s = PersistentStore::open_in_memory(limits()).unwrap();
        s.insert(&id(1), &share(Some(1), None, false), 0).unwrap();
        assert_eq!(
            s.revoke(&id(1), RevokeAuth::Token(b"bad"), 0),
            Err(StoreError::Forbidden)
        );
        s.revoke(&id(1), RevokeAuth::Token(b"rv"), 0).unwrap();
        assert_eq!(
            s.consume(&id(1), 0, AccessCheck::none()).unwrap_err(),
            StoreError::Unavailable
        );
    }

    #[test]
    fn concurrent_consumers_one_winner() {
        let s = Arc::new(PersistentStore::open_in_memory(limits()).unwrap());
        s.insert(&id(9), &share(Some(1), None, false), 0).unwrap();
        let handles: Vec<_> = (0..50)
            .map(|_| {
                let s = Arc::clone(&s);
                std::thread::spawn(move || s.consume(&id(9), 0, AccessCheck::none()).is_ok())
            })
            .collect();
        assert_eq!(
            handles
                .into_iter()
                .filter_map(|h| h.join().ok())
                .filter(|x| *x)
                .count(),
            1
        );
    }

    #[test]
    fn tokens_roundtrip_and_revoke() {
        let s = PersistentStore::open_in_memory(limits()).unwrap();
        let t = StoredToken {
            id: "cdt_abc".into(),
            name: "ci".into(),
            verifier: Verifier::from_secret(b"secret"),
            scopes: vec!["shares:create".into(), "shares:revoke".into()],
            created_at: 5,
            expires_at: Some(50),
            rate_limit_per_minute: Some(10),
            daily_create_quota: None,
        };
        s.insert_token(&t).unwrap();
        assert_eq!(s.insert_token(&t), Err(StoreError::Duplicate));
        assert_eq!(s.list_tokens().unwrap(), vec![t]);
        assert!(s.revoke_token("cdt_abc", 6).unwrap());
        assert!(!s.revoke_token("cdt_abc", 6).unwrap());
        assert!(s.list_tokens().unwrap().is_empty());
    }
}
