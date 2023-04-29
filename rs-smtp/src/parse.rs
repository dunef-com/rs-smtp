use std::{collections::HashMap};
use anyhow::{bail, Result};

pub fn parse_cmd(line: String) -> Result<(String, String)> {
    let line = line.trim_end_matches("\r\n");

    if line.to_uppercase().starts_with("STARTTLS") {
        return Ok(("STARTTLS".to_string(), "".to_string()));
    }

    let l = line.len();

    if l == 0 {
        return Ok(("".to_string(), "".to_string()));
    } else if l < 4 {
        bail!("Command too short: {}", line);
    } else if l == 4 {
        return Ok((line.to_uppercase(), "".to_string()));
    } else if l == 5 {
        bail!("Mangled command: {}", line);
    }

    if line.chars().nth(4) != Some(' ') {
		// There wasn't a space after the command?
		bail!("Mangled command: {}", line);
	}

    Ok((line[0..4].to_uppercase(), line[5..].trim_end_matches(" \r\n").to_string()))
}

pub fn parse_args(args: &[&str]) -> Result<HashMap<String, String>> {
    let mut arg_map = HashMap::new();

    for arg in args {
        if arg.len() == 0 {
            continue;
        }

        let mut parts = arg.split('=');
        match (parts.next(), parts.next()) {
            (Some(key), Some(value)) => {
                arg_map.insert(key.to_string(), value.to_string());
            }
            (Some(key), None) => {
                arg_map.insert(key.to_string(), "".to_string());
            }
            _ => bail!("Failed to parse arg string: {}", arg),
        }
    }

    Ok(arg_map)
}