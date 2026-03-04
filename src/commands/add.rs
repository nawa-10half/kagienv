use crate::vault::Vault;

pub fn execute(name: &str, value: &str) -> anyhow::Result<()> {
    let vault = Vault::open()?;
    vault.add(name, value)?;
    println!("Secret '{}' added.", name);
    Ok(())
}
