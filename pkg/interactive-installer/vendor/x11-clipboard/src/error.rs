use xcb::Atom;
use xcb::base::{ ConnError, GenericError };
use std::fmt;
use std::sync::mpsc::SendError;
use std::error::Error as StdError;

#[must_use]
#[derive(Debug)]
pub enum Error {
    Set(SendError<Atom>),
    XcbConn(ConnError),
    XcbGeneric(GenericError),
    Lock,
    Timeout,
    Owner
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;
        match self {
            Set(e) => write!(f, "{}: {:?}", self.description(), e),
            XcbConn(e) => write!(f, "{}: {:?}", self.description(), e),
            XcbGeneric(e) => write!(f, "{}: {:?}", self.description(), e),
            Lock | Timeout | Owner => write!(f, "{}", self.description()),
        }
    }
}

impl StdError for Error {
    fn description(&self) -> &str {
        use self::Error::*;
        match self {
            Set(_) => "XCB - couldn't set atom",
            XcbConn(_) => "XCB connection error",
            XcbGeneric(_) => "XCB generic error",
            Lock => "XCB: Lock is poisoned",
            Timeout => "Selection timed out",
            Owner => "Failed to set new owner of XCB selection",
        }
    }

    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        use self::Error::*;
        match self {
            Set(e) => Some(e),
            XcbConn(e) => Some(e),
            XcbGeneric(e) => Some(e),
            Lock | Timeout | Owner => None,
        }
    }

    fn cause(&self) -> Option<&dyn StdError> {
        self.source()
    }
}

macro_rules! define_from {
    ( $item:ident from $err:ty ) => {
        impl From<$err> for Error {
            fn from(err: $err) -> Error {
                Error::$item(err)
            }
        }
    }
}

define_from!(Set from SendError<Atom>);
define_from!(XcbConn from ConnError);
define_from!(XcbGeneric from GenericError);
