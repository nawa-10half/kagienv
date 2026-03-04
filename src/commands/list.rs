use crate::vault::Vault;

pub fn execute() -> anyhow::Result<()> {
    let vault = Vault::open()?;
    let entries = vault.list()?;

    if entries.is_empty() {
        println!("No secrets stored.");
        return Ok(());
    }

    let name_width = entries
        .iter()
        .map(|e| e.name.len())
        .max()
        .unwrap_or(4)
        .max(4); // minimum "NAME" width

    let time_width = 19; // "2026-03-04 13:58:59"
    let total_width = name_width + 2 + time_width + 2 + time_width;

    println!(
        "{:<nw$}  {:<tw$}  {:<tw$}",
        "NAME",
        "CREATED",
        "UPDATED",
        nw = name_width,
        tw = time_width
    );
    println!("{}", "-".repeat(total_width));
    for entry in &entries {
        println!(
            "{:<nw$}  {:<tw$}  {:<tw$}",
            entry.name,
            entry.created_at,
            entry.updated_at,
            nw = name_width,
            tw = time_width
        );
    }
    println!("\n{} secret(s) total.", entries.len());

    Ok(())
}
