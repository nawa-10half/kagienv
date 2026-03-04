use std::fs;
use std::io::{Read, Write};
use std::path::Path;

use age::secrecy::ExposeSecret;
use age::x25519::{Identity, Recipient};
use anyhow::{Context, Result};

/// Generate a new age x25519 identity and save it to the given path.
pub fn generate_identity(path: &Path) -> Result<Identity> {
    let identity = Identity::generate();
    let pubkey = identity.to_public();

    let contents = format!(
        "# public key: {}\n{}\n",
        pubkey,
        identity.to_string().expose_secret()
    );

    fs::write(path, contents)
        .with_context(|| format!("Failed to write identity to {}", path.display()))?;

    Ok(identity)
}

/// Load an existing age x25519 identity from a file.
pub fn load_identity(path: &Path) -> Result<Identity> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("Failed to read identity from {}", path.display()))?;

    let key_line = contents
        .lines()
        .find(|line| line.starts_with("AGE-SECRET-KEY-"))
        .context("No AGE-SECRET-KEY line found in identity file")?;

    key_line
        .parse::<Identity>()
        .map_err(|e| anyhow::anyhow!("Failed to parse identity: {}", e))
}

/// Encrypt a plaintext string using the given recipient (public key).
pub fn encrypt(plaintext: &str, recipient: &Recipient) -> Result<Vec<u8>> {
    let encryptor =
        age::Encryptor::with_recipients(std::iter::once(recipient as &dyn age::Recipient))
            .expect("we provided a recipient");

    let mut encrypted = vec![];
    let mut writer = encryptor
        .wrap_output(&mut encrypted)
        .context("Failed to initialize encryption")?;
    writer.write_all(plaintext.as_bytes())?;
    writer.finish()?;

    Ok(encrypted)
}

/// Decrypt a ciphertext blob using the given identity (private key).
pub fn decrypt(ciphertext: &[u8], identity: &Identity) -> Result<String> {
    let decryptor =
        age::Decryptor::new(ciphertext).context("Failed to initialize decryption")?;

    let mut decrypted = vec![];
    let mut reader = decryptor
        .decrypt(std::iter::once(identity as &dyn age::Identity))
        .context("Failed to decrypt (wrong key?)")?;
    reader.read_to_end(&mut decrypted)?;

    String::from_utf8(decrypted).context("Decrypted value is not valid UTF-8")
}
