use std::fs;
use std::error;
use std::fmt;
use std::io;

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
    keypairs: Vec<(String, String)>,
}

impl Config {
    pub fn new(config: String) -> Result<Self, Error> {
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
            let (_, keypair) = match table {
                (name, keypair) => (name, match keypair.as_table() {
                    Some(s) => s,
                    None => return Err(Error::ConfigurationError),
                }),
            };

            let (privkey, pubkey) =
                (keypair["privkey"].to_owned(), keypair["pubkey"].to_owned());

            // Add the pair to the vector
            match (privkey.as_str(), pubkey.as_str()) {
                (Some(privkey), Some(pubkey)) =>
                    keypairs.push((privkey.to_string(), pubkey.to_string())),
                _ => return Err(Error::ConfigurationError),
            }
        }

        Ok(Config { keypairs })
    }
}

