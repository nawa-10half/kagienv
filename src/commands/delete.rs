use crate::vault::Vault;

pub fn execute(name: &str) -> anyhow::Result<()> {
    let vault = Vault::open()?;
    vault.delete(name)?;
    println!("Secret '{}' deleted.", name);
    Ok(())
}
