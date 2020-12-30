use std::error;
use std::fmt;
use std::fs;
use std::io;
use std::path::PathBuf;

use toml;

#[derive(Debug)]
pub enum Error {
    IOError(io::Error),
    ParseError(toml::de::Error),
    ConfigurationError,
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Self::IOError(err)
    }
}

impl From<toml::de::Error> for Error {
    fn from(err: toml::de::Error) -> Self {
        Self::ParseError(err)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::IOError(_) =>
                write!(f, "Something went wrong trying to load the config file."),
            Self::ParseError(_) =>
                write!(f, "Something went wrong parsing the configuration file."),
            Self::ConfigurationError =>
                write!(f, "The software seems to be misconfigured."),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::IOError(err) => Some(err),
            Self::ParseError(err) => Some(err),
            Self::ConfigurationError => None,
        }
    }
}

#[derive(Debug)]
pub struct Config {
    pub keypairs: Vec<(String, String)>,
}

impl Config {
    pub fn new(config: PathBuf) -> Result<Self, Error> {
        // Parse the configuration file into a loopable set of keypair tables
        let raw: String = fs::read_to_string(config)?;
        let config: toml::Value = raw.parse()?;
        let tables = match config.as_table() {
            Some(s) => s,
            None => return Err(Error::ConfigurationError),
        };

        // Initialize a vector to store all the keypairs
        let mut keypairs: Vec<(String, String)> = Vec::new();

        // Loop over each keypair
        for table in tables {
            // Extract the actual table of keypairs from the ensuing mess
            let (_, keypair) = table;

            let keypair = match keypair.as_table() {
                Some(s) => s,
                None => return Err(Error::ConfigurationError),
            };

            // Make sure that both the public and private key are specified
            if !keypair.contains_key("pubkey") || !keypair.contains_key("privkey") {
                return Err(Error::ConfigurationError);
            }

            // Also make sure no other keys are specified
            if keypair.len() > 2 {
                return Err(Error::ConfigurationError);
            }

            let (privkey, pubkey) =
                (keypair["privkey"].to_owned(), keypair["pubkey"].to_owned());

            // Make sure the private and public key paths are both specified as strings
            if !privkey.is_str() || !pubkey.is_str() {
                return Err(Error::ConfigurationError);
            }

            // Add the pair to the keypairs vector, making sure they are both strings
            match (privkey.as_str(), pubkey.as_str()) {
                (Some(privkey), Some(pubkey)) =>
                    keypairs.push((privkey.to_string(), pubkey.to_string())),
                _ => return Err(Error::ConfigurationError),
            }
        }

        Ok(Config { keypairs })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_config() {
        let conf = Config::new(PathBuf::from("tests/config/i_dont_exist"));

        match conf {
            Err(Error::IOError(_)) => (),
            _ => panic!(),
        }
    }

    #[test]
    fn invalid_toml() {
        let conf = Config::new(PathBuf::from("tests/config/invalid_toml.toml"));

        match conf {
            Err(Error::ParseError(_)) => (),
            _ => panic!(),
        }
    }

    #[test]
    fn unneeded_fields() {
        let conf = Config::new(PathBuf::from("tests/config/unneeded_fields.toml"));

        match conf {
            Err(Error::ConfigurationError) => (),
            _ => panic!(),
        }
    }

    #[test]
    fn wrong_datatypes() {
        let conf = Config::new(PathBuf::from("tests/config/wrong_datatypes.toml"));

        match conf {
            Err(Error::ConfigurationError) => (),
            _ => panic!(),
        }
    }

    #[test]
    fn nested_sections() {
        let conf = Config::new(PathBuf::from("tests/config/nested_sections.toml"));

        match conf {
            Err(Error::ConfigurationError) => (),
            _ => panic!(),
        }
    }

    #[test]
    fn incomplete_fields() {
        let conf = Config::new(PathBuf::from("tests/config/incomplete_fields.toml"));

        match conf {
            Err(Error::ConfigurationError) => (),
            _ => panic!()
        }
    }

    #[test]
    fn proper_config() {
        let conf = Config::new(PathBuf::from("tests/config/proper_config.toml"));
        
        conf.unwrap();
    }
}
