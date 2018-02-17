#![feature(box_patterns)]

#[macro_use]
extern crate assert_matches;
extern crate iron;
extern crate iron_dsc_csrf;
extern crate iron_test;

use iron::prelude::*;
use iron::{headers, status, AroundMiddleware, BeforeMiddleware, Handler, Headers};

use iron_test::{request, response};

use iron_dsc_csrf::{Csrf, CsrfError, CsrfToken, SessionId};

struct HelloWorldHandler;

impl Handler for HelloWorldHandler {
    fn handle(&self, req: &mut Request) -> IronResult<Response> {
        let token = req.extensions.get::<CsrfToken>().unwrap();
        assert_eq!(44, token.len());

        Ok(Response::with((status::Ok, "Hello, world!")))
    }
}

struct SetToken {
    pub session_id: Option<SessionId>,
    pub token: Option<String>,
}

impl BeforeMiddleware for SetToken {
    fn before(&self, req: &mut Request) -> Result<(), IronError> {
        if let Some(ref x) = self.token {
            req.extensions.insert::<Token>(x.clone());
        }

        if let Some(ref x) = self.session_id {
            req.extensions.insert::<Id>(x.clone());
        }

        Ok(())
    }
}

struct Token;

impl iron::typemap::Key for Token {
    type Value = String;
}

struct Id;

impl iron::typemap::Key for Id {
    type Value = SessionId;
}

#[test]
fn hello_world_get() {
    let handler = Csrf::<Token, Id>::new().around(Box::new(HelloWorldHandler));
    let response = request::get("http://localhost:3000/hello", Headers::new(), &handler).unwrap();
    assert_eq!(response.status, Some(status::Ok));

    let result_body = response::extract_body_to_bytes(response);
    assert_eq!(result_body, b"Hello, world!");
}

#[test]
fn post_cookie_missing() {
    let handler = Csrf::<Token, Id>::new().around(Box::new(HelloWorldHandler));
    let err =
        request::post("http://localhost:3000/hello", Headers::new(), "", &handler).unwrap_err();

    assert_matches!(
        err.error.downcast::<CsrfError>().unwrap(),
        box CsrfError::CookieMissing
    );
    let response = err.response;
    assert_eq!(response.status, Some(status::BadRequest));
}

#[test]
fn post_token_missing() {
    let handler = Csrf::<Token, Id>::new().around(Box::new(HelloWorldHandler));

    let mut headers = Headers::new();
    headers.set(headers::Cookie(vec!["csrf=banana".to_owned()]));

    let err = request::post("http://localhost:3000/hello", headers, "", &handler).unwrap_err();

    assert_matches!(
        err.error.downcast::<CsrfError>().unwrap(),
        box CsrfError::TokenMissing
    );
    let response = err.response;
    assert_eq!(response.status, Some(status::BadRequest));
}

#[test]
fn post_token_invalid() {
    let handler = Csrf::<Token, Id>::new().around(Box::new(HelloWorldHandler));
    let mut chain = Chain::new(handler);
    chain.link_before(SetToken {
        session_id: None,
        token: Some("orange".to_owned()),
    });

    let mut headers = Headers::new();
    headers.set(headers::Cookie(vec!["csrf=banana".to_owned()]));

    let err = request::post("http://localhost:3000/hello", headers, "", &chain).unwrap_err();

    assert_matches!(
        err.error.downcast::<CsrfError>().unwrap(),
        box CsrfError::TokenInvalid
    );
    let response = err.response;
    assert_eq!(response.status, Some(status::BadRequest));
}

const CSRF: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[test]
fn post_token_missing_length() {
    let handler = Csrf::<Token, Id>::new().around(Box::new(HelloWorldHandler));
    let mut chain = Chain::new(handler);
    chain.link_before(SetToken {
        session_id: None,
        token: Some(CSRF.to_owned()),
    });

    let mut headers = Headers::new();
    headers.set(headers::Cookie(vec!["csrf=banana".to_owned()]));

    let err = request::post("http://localhost:3000/hello", headers, "", &chain).unwrap_err();

    assert_matches!(
        err.error.downcast::<CsrfError>().unwrap(),
        box CsrfError::TokenMissing
    );
    let response = err.response;
    assert_eq!(response.status, Some(status::BadRequest));
}

#[test]
fn hello_world_post() {
    let handler = Csrf::<Token, Id>::new().around(Box::new(HelloWorldHandler));
    let mut chain = Chain::new(handler);
    chain.link_before(SetToken {
        session_id: None,
        token: Some(CSRF.to_owned()),
    });

    let mut headers = Headers::new();
    headers.set(headers::Cookie(vec![format!("csrf={}", CSRF)]));

    let response = request::post("http://localhost:3000/hello", headers, "", &chain).unwrap();

    assert_eq!(response.status, Some(status::Ok));

    let result_body = response::extract_body_to_bytes(response);
    assert_eq!(result_body, b"Hello, world!");
}

#[test]
fn post_chain_around() {
    let mut chain = Chain::new(HelloWorldHandler);
    let handler = Csrf::<Token, Id>::new();

    chain.link_around(handler);
    chain.link_before(SetToken {
        session_id: None,
        token: Some(CSRF.to_owned()),
    });

    let mut headers = Headers::new();
    headers.set(headers::Cookie(vec![format!("csrf={}", CSRF)]));

    let response = request::post("http://localhost:3000/hello", headers, "", &chain).unwrap();

    assert_eq!(response.status, Some(status::Ok));

    let result_body = response::extract_body_to_bytes(response);
    assert_eq!(result_body, b"Hello, world!");
}
