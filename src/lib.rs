#![cfg_attr(test, allow(new_without_default_derive))] // Seems broken in clippy 0.0.186
#![cfg_attr(test, feature(plugin))]
#![cfg_attr(test, plugin(clippy))]
#![deny(missing_docs)]

//! Iron middleware providing cross-site request forgery (CSRF) protection.
//!
//! ## Overview
//!
//! `iron-dsc-csrf` is used as an `Iron::AroundMiddleware` that checks unsafe
//! HTTP methods (for example POST, PUT, and PATCH) for a valid CSRF token.
//!
//! ## Implementation
//!
//! `iron-dsc-csrf` uses a method called Double Submit Cookie (or DSC). On the
//! first request to a protected handler, `iron-dsc-csrf` generates a long
//! random value, called the token. The token is placed into a cookie and
//! provided to the client in the response.
//!
//! When a client makes an unsafe request, it must provide the token in a way
//! that cannot be triggered without user action and intent. The usual method of
//! providing the token is with a hidden input field in a form.
//!
//! Upon receiving the unsafe request, `iron-dsc-csrf` compares the token from
//! the cookie to the token in the submitted data. If the tokens match, the
//! request is allowed, otherwise it is denied.
//!
//! ## Usage
//!
//! ```
//! extern crate iron_dsc_csrf;
//! extern crate iron;
//!
//! use iron_dsc_csrf::{Csrf, CsrfToken, SessionId};
//! use iron::BeforeMiddleware;
//! use iron::prelude::*;
//! use iron::status;
//!
//! struct Token;
//!
//! impl iron::typemap::Key for Token {
//!     type Value = String;
//! }
//!
//! struct Id;
//!
//! impl iron::typemap::Key for Id {
//!     type Value = SessionId;
//! }
//!
//! struct SetToken;
//!
//! impl BeforeMiddleware for SetToken {
//!     fn before(&self, req: &mut Request) -> Result<(), IronError> {
//!         // Here you can extract the token from the form body, the query string,
//!         // or anywhere else you like. In this simple example, we treat the
//!         // entire query string as the CSRF token.
//!
//!         if let Some(x) = req.url.query().map(|x| x.to_owned()) {
//!             req.extensions.insert::<Token>(x);
//!         }
//!
//!         Ok(())
//!     }
//! }
//!
//! fn main() {
//!     let mut chain = Chain::new(index);
//!     chain.link_around(Csrf::<Token, Id>::new());
//!     chain.link_before(SetToken);
//!
//!     // Make and start the server
//!     //Iron::new(chain).http("localhost:8080").unwrap();
//! }
//!
//! fn index(request: &mut Request) -> IronResult<Response> {
//!     let token = request.extensions.get::<CsrfToken>().unwrap();
//!     let msg = format!("Hello, CSRF Token: {}", token);
//!     Ok(Response::with((status::Ok, msg)))
//! }
//! ```

extern crate base64;
extern crate cookie;
extern crate iron;
extern crate rand;
extern crate subtle;

use cookie::Cookie;

use iron::prelude::*;
use iron::{headers, typemap, AroundMiddleware, Handler, Headers};

use rand::{OsRng, Rng};

use std::marker::PhantomData;
use std::net::IpAddr;

use subtle::slices_equal;

mod errors;

pub use errors::CsrfError;

const COOKIE_NAME: &str = "csrf";

/// A unique identifier that can be assigned to all requests in the same session
#[derive(Debug, Clone)]
pub enum SessionId {
    /// Represents a session that is not yet authenticated
    Anonymous(IpAddr),

    /// Represents a session that has been authenticated (with a user name)
    Identified(String),
}

/// Convenience trait for representing a token key in an
/// `iron::typemap::TypeMap`
pub trait Key<V>: typemap::Key<Value = V> + Send + Sync
where
    V: 'static,
{
}
impl<T, V> Key<V> for T
where
    T: typemap::Key<Value = V> + Send + Sync,
    V: 'static,
{
}

/// An `iron::AroundMiddleware` that provides CSRF protection.
#[derive(Default)]
pub struct Csrf<T, I>
where
    T: Key<String>,
    I: Key<SessionId>,
{
    t: PhantomData<T>,
    i: PhantomData<I>,
}

impl<T, I> Csrf<T, I>
where
    T: Key<String>,
    I: Key<SessionId>,
{
    /// Create a new instance of `Csrf`
    pub fn new() -> Self {
        Csrf {
            t: PhantomData,
            i: PhantomData,
        }
    }
}

/// The key for the CSRF token in an `iron::typemap::TypeMap`
pub struct CsrfToken;

impl typemap::Key for CsrfToken {
    type Value = String;
}

impl<T, I> AroundMiddleware for Csrf<T, I>
where
    T: Key<String>,
    I: Key<SessionId>,
{
    fn around(self, handler: Box<Handler>) -> Box<Handler> {
        Box::new(CsrfHandler {
            handler: handler,
            _csrf: self,
        })
    }
}

struct CsrfHandler<T, I>
where
    T: Key<String>,
    I: Key<SessionId>,
{
    handler: Box<Handler>,
    _csrf: Csrf<T, I>,
}

impl<T, I> Handler for CsrfHandler<T, I>
where
    T: Key<String>,
    I: Key<SessionId>,
{
    fn handle(&self, req: &mut Request) -> IronResult<Response> {
        let state = self.before(req)?;
        let res = self.handler.handle(req)?;
        self.after(state, res)
    }
}

impl<T, I> CsrfHandler<T, I>
where
    T: Key<String>,
    I: Key<SessionId>,
{
    fn before(&self, req: &mut Request) -> IronResult<Option<Cookie>> {
        let cookie = self.find_csrf_cookie(&req.headers);
        self.verify_csrf(req, cookie.as_ref())?;

        let (csrf_token, set_cookie) = match cookie {
            Some(c) => (c.value().to_owned(), None),
            None => Self::generate_token()?,
        };

        req.extensions.insert::<CsrfToken>(csrf_token);

        Ok(set_cookie)
    }

    fn find_csrf_cookie<'a>(&self, hdrs: &'a Headers) -> Option<Cookie<'a>> {
        let cookies = match hdrs.get::<headers::Cookie>() {
            Some(c) => c,
            None => return None,
        };

        cookies
            .iter()
            .filter_map(|raw_cookie| {
                let parsed_cookie = match Cookie::parse(raw_cookie.as_ref()) {
                    Ok(c) => c,
                    Err(_) => return None,
                };

                if COOKIE_NAME == parsed_cookie.name() {
                    Some(parsed_cookie)
                } else {
                    None
                }
            })
            .nth(0)
    }

    fn generate_token() -> IronResult<(String, Option<Cookie<'static>>)> {
        let mut rng = OsRng::new().map_err(CsrfError::NoRandom)?;

        let mut token_bytes = [0u8; 32];

        rng.fill_bytes(&mut token_bytes);

        let token = base64::encode(&token_bytes);

        Ok((token.clone(), Some(Cookie::new(COOKIE_NAME, token))))
    }

    fn verify_csrf(&self, req: &Request, cookie: Option<&Cookie>) -> IronResult<()> {
        if req.method.safe() {
            return Ok(());
        }

        let cookie = match cookie {
            Some(c) => c,
            None => return Err(CsrfError::CookieMissing.into()),
        };

        let token = match req.extensions.get::<T>() {
            Some(x) => x,
            None => return Err(CsrfError::TokenMissing.into()),
        };

        let cookie_bytes = base64::decode(cookie.value()).or(Err(CsrfError::CookieMissing))?;

        let token_bytes = base64::decode(&token).or(Err(CsrfError::TokenInvalid))?;

        if token_bytes.len() != cookie_bytes.len() {
            return Err(CsrfError::TokenMissing.into());
        }

        if 1 == slices_equal(&cookie_bytes, &token_bytes) {
            Ok(())
        } else {
            Err(CsrfError::TokenInvalid.into())
        }
    }

    fn after<'a>(&self, set_cookie: Option<Cookie<'a>>, mut res: Response) -> IronResult<Response> {
        if let Some(set_cookie) = set_cookie {
            let header = if res.headers.has::<headers::SetCookie>() {
                res.headers.get_mut::<headers::SetCookie>()
            } else {
                res.headers.set(headers::SetCookie(vec![]));
                res.headers.get_mut::<headers::SetCookie>()
            }.unwrap();

            header.push(set_cookie.to_string());
        }

        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iron::status;

    struct Token {}
    impl typemap::Key for Token {
        type Value = String;
    }

    struct Id {}
    impl typemap::Key for Id {
        type Value = SessionId;
    }

    fn new_impl_none() -> CsrfHandler<Token, Id> {
        CsrfHandler {
            handler: Box::new(|_: &mut Request| Ok(Response::with(status::NoContent))),
            _csrf: Csrf {
                i: PhantomData,
                t: PhantomData,
            },
        }
    }

    #[test]
    fn generate_token() {
        let (token, cookie) = CsrfHandler::<Token, Id>::generate_token().unwrap();
        assert_eq!(token, cookie.unwrap().value());
        assert!(token.is_ascii());
        assert_eq!(44, token.len());
    }

    #[test]
    fn after_no_cookie() {
        let csrf = new_impl_none();
        let expected = Response::with(status::NoContent);
        let input = Response::with(status::NoContent);

        let actual = csrf.after(None, input).unwrap();

        assert_eq!(expected.status, actual.status);
        assert_eq!(expected.headers, actual.headers);
        assert!(expected.extensions.is_empty());
    }

    #[test]
    fn after_set_cookie() {
        let csrf = new_impl_none();
        let mut expected = Response::with(status::NoContent);
        expected
            .headers
            .set(headers::SetCookie(vec!["hello=world".to_owned()]));

        let cookie = Cookie::new("hello", "world");

        let input = Response::with(status::NoContent);
        let actual = csrf.after(Some(cookie), input).unwrap();

        assert_eq!(expected.status, actual.status);
        assert_eq!(expected.headers, actual.headers);
        assert!(expected.extensions.is_empty());
    }

    #[test]
    fn after_append_cookie() {
        let csrf = new_impl_none();
        let mut expected = Response::with(status::NoContent);
        expected.headers.set(headers::SetCookie(vec![
            "orange=banana".to_owned(),
            "hello=world".to_owned(),
        ]));

        let cookie = Cookie::new("hello", "world");

        let mut input = Response::with(status::NoContent);
        input
            .headers
            .set(headers::SetCookie(vec!["orange=banana".to_owned()]));
        let actual = csrf.after(Some(cookie), input).unwrap();

        assert_eq!(expected.status, actual.status);
        assert_eq!(expected.headers, actual.headers);
        assert!(expected.extensions.is_empty());
    }
}
