use std::path::Path;

use anyhow::{Context, Result};
use rusqlite::Connection;

/// A record returned by list operations (no decrypted value).
pub struct SecretEntry {
    pub name: String,
    pub created_at: String,
    pub updated_at: String,
}

/// Open (or create) the SQLite database and ensure schema exists.
pub fn open_db(path: &Path) -> Result<Connection> {
    let conn = Connection::open(path)
        .with_context(|| format!("Failed to open database at {}", path.display()))?;

    conn.pragma_update(None, "journal_mode", "WAL")?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS secrets (
            name            TEXT PRIMARY KEY NOT NULL,
            encrypted_value BLOB NOT NULL,
            created_at      TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
        )",
        (),
    )
    .context("Failed to create secrets table")?;

    Ok(conn)
}

/// Insert or update a secret.
pub fn upsert_secret(conn: &Connection, name: &str, encrypted_value: &[u8]) -> Result<()> {
    conn.execute(
        "INSERT INTO secrets (name, encrypted_value, created_at, updated_at)
         VALUES (?1, ?2, datetime('now'), datetime('now'))
         ON CONFLICT(name) DO UPDATE SET
             encrypted_value = excluded.encrypted_value,
             updated_at = datetime('now')",
        (name, encrypted_value),
    )
    .with_context(|| format!("Failed to upsert secret '{}'", name))?;

    Ok(())
}

/// List all secret entries (name + timestamps, no values).
pub fn list_secrets(conn: &Connection) -> Result<Vec<SecretEntry>> {
    let mut stmt = conn
        .prepare("SELECT name, datetime(created_at, 'localtime'), datetime(updated_at, 'localtime') FROM secrets ORDER BY name")
        .context("Failed to prepare list query")?;

    let entries = stmt
        .query_map([], |row| {
            Ok(SecretEntry {
                name: row.get(0)?,
                created_at: row.get(1)?,
                updated_at: row.get(2)?,
            })
        })
        .context("Failed to execute list query")?
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("Failed to read secret entries")?;

    Ok(entries)
}

/// Get the encrypted value for a single secret by name.
pub fn get_secret(conn: &Connection, name: &str) -> Result<Vec<u8>> {
    conn.query_row(
        "SELECT encrypted_value FROM secrets WHERE name = ?1",
        [name],
        |row| row.get(0),
    )
    .with_context(|| format!("Secret '{}' not found", name))
}

/// Get all secrets (name + encrypted_value).
pub fn get_all_secrets(conn: &Connection) -> Result<Vec<(String, Vec<u8>)>> {
    let mut stmt = conn
        .prepare("SELECT name, encrypted_value FROM secrets ORDER BY name")
        .context("Failed to prepare get_all query")?;

    let entries = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .context("Failed to execute get_all query")?
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("Failed to read secrets")?;

    Ok(entries)
}

/// Delete a secret by name. Returns an error if the secret doesn't exist.
pub fn delete_secret(conn: &Connection, name: &str) -> Result<()> {
    let affected = conn
        .execute("DELETE FROM secrets WHERE name = ?1", [name])
        .with_context(|| format!("Failed to delete secret '{}'", name))?;

    if affected == 0 {
        anyhow::bail!("Secret '{}' not found", name);
    }

    Ok(())
}
