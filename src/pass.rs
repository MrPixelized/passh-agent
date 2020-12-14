use std::process::Command;

/// Get a datum from pass using the `pass show' command.
pub fn query(key: String) -> Result<String, String> {
    let output = Command::new("pass")
        .arg("show")
        .arg(key)
        .output()
        .expect("Failed to call Pass binary");

    let res = String::from_utf8(output.stdout)
        .expect("Pass output has invalid format");

    Ok(res)
}
