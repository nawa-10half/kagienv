use std::process::{self, Command};

use anyhow::{bail, Context};

use crate::vault::Vault;

pub fn execute(command: &[String]) -> anyhow::Result<()> {
    let Some((program, args)) = command.split_first() else {
        bail!("No command specified");
    };

    let vault = Vault::open()?;
    let secrets = vault.get_all()?;

    let status = Command::new(program)
        .args(args)
        .envs(secrets.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .status()
        .with_context(|| format!("Failed to execute '{}'", program))?;

    process::exit(status.code().unwrap_or(1));
}
