extern crate iron;
extern crate iron_dsc_csrf;

use iron_dsc_csrf::{Csrf, CsrfToken, SessionId};
use iron::BeforeMiddleware;
use iron::prelude::*;
use iron::status;

struct Token;

impl iron::typemap::Key for Token {
    type Value = String;
}

struct Id;

impl iron::typemap::Key for Id {
    type Value = SessionId;
}

struct SetToken;

impl BeforeMiddleware for SetToken {
    fn before(&self, req: &mut Request) -> Result<(), IronError> {
        // Here you can extract the token from the form body, the query string,
        // or anywhere else you like. In this simple example, we treat the
        // entire query string as the CSRF token.

        if let Some(x) = req.url.query().map(|x| x.to_owned()) {
            req.extensions.insert::<Token>(x);
        }

        Ok(())
    }
}

fn main() {
    let mut chain = Chain::new(index);
    chain.link_around(Csrf::<Token, Id>::new());
    chain.link_before(SetToken);

    // Make and start the server
    Iron::new(chain).http("localhost:8080").unwrap();
}

fn index(request: &mut Request) -> IronResult<Response> {
    let token = request.extensions.get::<CsrfToken>().unwrap();
    let msg = format!("Hello, CSRF Token: {}", token);
    Ok(Response::with((status::Ok, msg)))
}
