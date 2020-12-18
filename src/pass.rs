use std::process::Command;
use std::path::PathBuf;

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

/// Query pass for its full password tree,
/// return a list of paths (PathBuf objects).
pub fn get_paths() -> Result<Vec<PathBuf>, String> {
    // Call the pass command.
    let output = Command::new("pass")
        .arg("ls")
        .output()
        .expect("Failed to call Pass binary");

    // Split the output into a set of lines
    let lines: Vec<String> = String::from_utf8(output.stdout)
        .expect("Pass output has invalid format")
        .lines()
        .map(|c| String::from(c))
        .collect();

    // TODO: Filter ANSI color codes from this output

    // Isolate the tree from the output and return the paths
    // represented by this tree
    tree_to_paths(Vec::from(&lines[1..]))
}

/// Take in a list of lines of tree output,
/// return a list of path-looking strings.
// TODO: Error handling for this function
fn tree_to_paths(lines: Vec<String>) -> Result<Vec<PathBuf>, String> {
    // List the tokens which indicate the start of indentation in the tree.
    let tokens = ["├── ", "└── "];

    // Translate the lines and tokens from strings to vectors of characters.
    let lines: Vec<_> = lines.iter()
        .map(|x| x.chars().collect::<Vec<_>>())
        .collect();
    let tokens: Vec<_> = tokens.iter()
        .map(|x| x.chars().collect::<Vec<_>>())
        .collect();

    // Intialize the vector to store the generated paths.
    let mut paths: Vec<PathBuf> = Vec::new();

    // Initialize the starting index of a found subtree to 0 and
    // set the name of the folder of this subtree
    let mut entry_idx = 0;

    for i in 1..lines.len() + 1 {
        // If a next token is found or the end of the tree has been reached,
        // compute the paths of entry_idx..i.
        if i == lines.len() || tokens.iter().any(|token| lines[i].starts_with(&token[..])) {
            // Get the top-level path of the found indentation
            let path_parent = PathBuf::from(lines[entry_idx][4..].iter().collect::<String>());

            if entry_idx + 1 == i {
                // If the newly found token is just one after the entry index,
                // no indentation has occurred; add the current item to the path list.
                paths.push(path_parent);
            } else {
                // A new indentation token (or end of lines) has been reached,
                // slice the lines from entry idx to here into a new subtree.
                let indentation = lines[entry_idx + 1..i]
                    .iter()
                    .map(|ln| ln[4..].iter().collect::<String>())
                    .collect();

                // Find the paths of the subtree.
                // Make sure to prepend the current folder to the paths.
                let children: Vec<PathBuf> = tree_to_paths(indentation)?
                    .iter()
                    .map(|path| path_parent.join(path))
                    .collect();

                // Add the paths in this block to all the found paths.
                paths.extend(children);
            }

            // Start looking for a subtree again from the current index.
            entry_idx = i;
        }
    }

    Ok(paths)
}

/// Return a vector of all paths to password-store files,
/// where each path contains `query'.
pub fn find(query: &String) -> Result<Vec<String>, String> {
    let paths = get_paths()?
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .filter(|p| p.contains(&query[..]))
        .collect();

    Ok(paths)
}
