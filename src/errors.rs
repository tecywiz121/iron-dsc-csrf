use iron::{self, status, IronError, Response};

use std::convert::From;
use std::error::Error;
use std::fmt;

/// The type of Errors used in this middleware.
///
/// Used to convey extra information inside an `iron::IronError`
#[derive(Debug)]
pub enum CsrfError {
    /// No token was provided with the request
    TokenMissing,

    /// A token was provided, but it didn't match the cookie
    TokenInvalid,

    /// No cookie was provided with the request
    CookieMissing,

    /// An error was encountered while generating a random token
    NoRandom(::std::io::Error),
}

impl CsrfError {
    fn http_status(&self) -> status::Status {
        use CsrfError::*;

        match *self {
            NoRandom(_) => status::InternalServerError,
            _ => status::BadRequest,
        }
    }
}

impl Error for CsrfError {
    fn description(&self) -> &str {
        use CsrfError::*;

        match *self {
            TokenMissing => "csrf token is missing",
            TokenInvalid => "csrf token is invalid",
            CookieMissing => "csrf cookie is missing",
            NoRandom(_) => "failed to generate random bytes",
        }
    }

    fn cause(&self) -> Option<&Error> {
        match *self {
            CsrfError::NoRandom(ref x) => Some(x),
            _ => None,
        }
    }
}

impl fmt::Display for CsrfError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.description())
    }
}

impl From<CsrfError> for iron::IronError {
    fn from(f: CsrfError) -> Self {
        IronError {
            response: Response::with((f.http_status(), f.description())),
            error: Box::new(f),
        }
    }
}
