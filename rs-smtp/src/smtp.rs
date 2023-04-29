use anyhow::{bail, Result};

pub fn validate_line(line: String) -> Result<()> {
    if line.contains("\n\r") {
        bail!("A line must not contain CR or LF");
    }
    
	return Ok(())
}