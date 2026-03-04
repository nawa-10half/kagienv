use std::fs;
use std::io::{Read, Write};
use std::path::Path;

use age::secrecy::{ExposeSecret, SecretString};
use age::x25519::{Identity, Recipient};
use anyhow::{Context, Result};

// ---------------------------------------------------------------------------
// Public API (signatures unchanged)
// ---------------------------------------------------------------------------

/// Generate a new age x25519 identity and save it in a protected form.
pub fn generate_identity(path: &Path) -> Result<Identity> {
    let identity = Identity::generate();

    if should_use_keychain() {
        #[cfg(target_os = "macos")]
        {
            save_to_keychain(&identity)?;
            save_public_key_only(path, &identity)?;
        }
        #[cfg(not(target_os = "macos"))]
        {
            // Fallback — should not reach here because should_use_keychain()
            // returns false on non-macOS, but handle it gracefully.
            let password = prompt_password_confirm()?;
            let encrypted = passphrase_encrypt_identity(&identity, &password)?;
            fs::write(path, encrypted)
                .with_context(|| format!("Failed to write identity to {}", path.display()))?;
        }
    } else {
        let password = prompt_password_confirm()?;
        let encrypted = passphrase_encrypt_identity(&identity, &password)?;
        fs::write(path, encrypted)
            .with_context(|| format!("Failed to write identity to {}", path.display()))?;
    }

    Ok(identity)
}

/// Load an existing age x25519 identity from a file (or Keychain).
pub fn load_identity(path: &Path) -> Result<Identity> {
    match detect_identity_format(path)? {
        IdentityFormat::Plaintext => {
            let identity = load_plaintext_identity(path)?;
            migrate_plaintext_identity(path, &identity)?;
            Ok(identity)
        }
        IdentityFormat::PublicKeyOnly => {
            #[cfg(target_os = "macos")]
            {
                load_from_keychain()
            }
            #[cfg(not(target_os = "macos"))]
            {
                anyhow::bail!(
                    "identity.txt contains only a public key but macOS Keychain is not available"
                )
            }
        }
        IdentityFormat::PassphraseEncrypted => {
            let password = prompt_password("Master password: ")?;
            passphrase_decrypt_identity(path, &password)
        }
    }
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

// ---------------------------------------------------------------------------
// Identity format detection
// ---------------------------------------------------------------------------

enum IdentityFormat {
    /// Legacy: file contains `AGE-SECRET-KEY-` in plain text.
    Plaintext,
    /// macOS mode: file contains only `# public key: age1...`, secret key is in Keychain.
    PublicKeyOnly,
    /// Linux/Windows mode: file is age-passphrase-encrypted binary.
    PassphraseEncrypted,
}

fn detect_identity_format(path: &Path) -> Result<IdentityFormat> {
    let raw = fs::read(path)
        .with_context(|| format!("Failed to read identity file: {}", path.display()))?;

    // Check for age encryption header (binary format).
    if raw.starts_with(b"age-encryption.org/v1") {
        return Ok(IdentityFormat::PassphraseEncrypted);
    }

    // It's a text file — inspect lines.
    let text = String::from_utf8_lossy(&raw);
    if text.lines().any(|l| l.starts_with("AGE-SECRET-KEY-")) {
        return Ok(IdentityFormat::Plaintext);
    }

    // No secret key line → assume public-key-only (macOS Keychain mode).
    Ok(IdentityFormat::PublicKeyOnly)
}

// ---------------------------------------------------------------------------
// Platform detection
// ---------------------------------------------------------------------------

fn should_use_keychain() -> bool {
    if std::env::var("SHUSH_USE_PASSWORD").is_ok() {
        return false;
    }
    cfg!(target_os = "macos")
}

// ---------------------------------------------------------------------------
// Legacy plaintext helpers
// ---------------------------------------------------------------------------

fn load_plaintext_identity(path: &Path) -> Result<Identity> {
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

/// Migrate a plaintext identity to the platform-appropriate protected format.
fn migrate_plaintext_identity(path: &Path, identity: &Identity) -> Result<()> {
    if should_use_keychain() {
        #[cfg(target_os = "macos")]
        {
            save_to_keychain(identity)?;
            save_public_key_only(path, identity)?;
            eprintln!("Migrated identity to macOS Keychain.");
        }
    } else {
        eprintln!("Your identity key is stored in plain text.");
        eprintln!("Setting up master password protection...");
        let password = prompt_password_confirm()?;
        let encrypted = passphrase_encrypt_identity(identity, &password)?;
        fs::write(path, encrypted)
            .with_context(|| format!("Failed to write encrypted identity to {}", path.display()))?;
        eprintln!("Migrated identity to passphrase-encrypted format.");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// macOS Keychain helpers + Touch ID via LocalAuthentication
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
const KEYCHAIN_SERVICE: &str = "shush";
#[cfg(target_os = "macos")]
const KEYCHAIN_ACCOUNT: &str = "identity";

#[cfg(target_os = "macos")]
fn save_to_keychain(identity: &Identity) -> Result<()> {
    use security_framework::passwords::{delete_generic_password, set_generic_password};

    let secret = identity.to_string();
    let secret_bytes = secret.expose_secret().as_bytes();

    let _ = delete_generic_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT);
    set_generic_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT, secret_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to save identity to macOS Keychain: {}", e))
}

#[cfg(target_os = "macos")]
fn load_from_keychain() -> Result<Identity> {
    use security_framework::passwords::get_generic_password;

    let secret_bytes = get_generic_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT)
        .map_err(|e| anyhow::anyhow!("Failed to retrieve identity from macOS Keychain: {}", e))?;

    let secret_str =
        String::from_utf8(secret_bytes).context("Keychain data is not valid UTF-8")?;
    let key_line = secret_str
        .lines()
        .find(|l| l.starts_with("AGE-SECRET-KEY-"))
        .context("Keychain data does not contain an AGE-SECRET-KEY line")?;

    key_line
        .parse::<Identity>()
        .map_err(|e| anyhow::anyhow!("Failed to parse identity from Keychain: {}", e))
}

#[cfg(target_os = "macos")]
fn save_public_key_only(path: &Path, identity: &Identity) -> Result<()> {
    let pubkey = identity.to_public();
    let contents = format!("# public key: {}\n", pubkey);
    fs::write(path, contents)
        .with_context(|| format!("Failed to write public key to {}", path.display()))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Passphrase encryption / decryption
// ---------------------------------------------------------------------------

fn passphrase_encrypt_identity(identity: &Identity, password: &str) -> Result<Vec<u8>> {
    let secret_key_str = identity.to_string();
    let plaintext = secret_key_str.expose_secret();
    let passphrase = SecretString::from(password.to_string());
    let encryptor = age::Encryptor::with_user_passphrase(passphrase);

    let mut encrypted = vec![];
    let mut writer = encryptor
        .wrap_output(&mut encrypted)
        .context("Failed to initialize passphrase encryption")?;
    writer.write_all(plaintext.as_bytes())?;
    writer.finish()?;

    Ok(encrypted)
}

fn passphrase_decrypt_identity(path: &Path, password: &str) -> Result<Identity> {
    let ciphertext = fs::read(path)
        .with_context(|| format!("Failed to read encrypted identity from {}", path.display()))?;

    let decryptor =
        age::Decryptor::new(ciphertext.as_slice()).context("Failed to parse encrypted identity")?;
    let passphrase = SecretString::from(password.to_string());
    let scrypt_identity = age::scrypt::Identity::new(passphrase);

    let mut decrypted = vec![];
    let mut reader = decryptor
        .decrypt(std::iter::once(&scrypt_identity as &dyn age::Identity))
        .context("Failed to decrypt identity (wrong password?)")?;
    reader.read_to_end(&mut decrypted)?;

    let key_str = String::from_utf8(decrypted).context("Decrypted identity is not valid UTF-8")?;
    let key_line = key_str
        .lines()
        .find(|l| l.starts_with("AGE-SECRET-KEY-"))
        .context("Decrypted data does not contain an AGE-SECRET-KEY line")?;

    key_line
        .parse::<Identity>()
        .map_err(|e| anyhow::anyhow!("Failed to parse decrypted identity: {}", e))
}

// ---------------------------------------------------------------------------
// Password prompts
// ---------------------------------------------------------------------------

fn prompt_password(prompt: &str) -> Result<String> {
    rpassword::prompt_password(prompt).context("Failed to read password")
}

fn prompt_password_confirm() -> Result<String> {
    loop {
        let p1 = rpassword::prompt_password("Set master password: ")
            .context("Failed to read password")?;
        let p2 = rpassword::prompt_password("Confirm master password: ")
            .context("Failed to read password")?;
        if p1 == p2 {
            return Ok(p1);
        }
        eprintln!("Passwords do not match. Please try again.");
    }
}
