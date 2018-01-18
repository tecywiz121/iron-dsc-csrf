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
//! use iron_dsc_csrf::Csrf;
//! use iron::AroundMiddleware;
//! use iron::prelude::*;
//! use iron::status;
//!
//! fn main() {
//!     let csrf = Csrf::new(extract_token);
//!
//!     let handler = csrf.around(Box::new(index));
//!
//!     // Make and start the server
//!     Iron::new(handler); //.http("localhost:8080").unwrap();
//! }
//!
//! fn extract_token(request: &Request) -> Option<String> {
//!     // Here you can extract the token from the form body, the query string,
//!     // or anywhere else you like.
//!
//!     request.url.query().map(|x| x.to_owned())
//! }
//!
//! fn index(request: &mut Request) -> IronResult<Response> {
//!     let token = request.extensions.get::<Csrf>().unwrap();
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

use subtle::slices_equal;

mod errors;

pub use errors::CsrfError;

const COOKIE_NAME: &str = "csrf";

/// An `iron::AroundMiddleware` that provides CSRF protection.
pub struct Csrf {
    extract_token: Box<Fn(&Request) -> Option<String> + Sync + Send>,
}

impl Csrf {
    /// Create a new instance of `Csrf` given a function to extract the CSRF
    /// token from a request.
    pub fn new<K: Fn(&Request) -> Option<String> + Sync + Send + 'static>(
        extract_token: K,
    ) -> Self {
        Csrf {
            extract_token: Box::new(extract_token),
        }
    }
}

impl typemap::Key for Csrf {
    type Value = String;
}

impl AroundMiddleware for Csrf {
    fn around(self, handler: Box<Handler>) -> Box<Handler> {
        Box::new(CsrfHandler {
            handler: handler,
            csrf: self,
        })
    }
}

struct CsrfHandler {
    handler: Box<Handler>,
    csrf: Csrf,
}

impl Handler for CsrfHandler {
    fn handle(&self, req: &mut Request) -> IronResult<Response> {
        let state = self.before(req)?;
        let res = self.handler.handle(req)?;
        self.after(state, res)
    }
}

impl CsrfHandler {
    fn before(&self, req: &mut Request) -> IronResult<Option<Cookie>> {
        let cookie = self.find_csrf_cookie(&req.headers);
        self.verify_csrf(req, cookie.as_ref())?;

        let (csrf_token, set_cookie) = match cookie {
            Some(c) => (c.value().to_owned(), None),
            None => Self::generate_token()?,
        };

        req.extensions.insert::<Csrf>(csrf_token);

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

        let token = match (self.csrf.extract_token)(req) {
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

    fn new_impl_none() -> CsrfHandler {
        CsrfHandler {
            handler: Box::new(|_: &mut Request| Ok(Response::with(status::NoContent))),
            csrf: Csrf {
                extract_token: Box::new(|_| None),
            },
        }
    }

    #[test]
    fn generate_token() {
        let (token, cookie) = CsrfHandler::generate_token().unwrap();
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
