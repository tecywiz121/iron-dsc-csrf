extern crate iron_dsc_csrf;
extern crate iron;

use iron_dsc_csrf::Csrf;
use iron::AroundMiddleware;
use iron::prelude::*;
use iron::status;

fn main() {
    let csrf = Csrf::new(extract_token);

    let handler = csrf.around(Box::new(index));

    // Make and start the server
    Iron::new(handler).http("localhost:8080").unwrap();
}

fn extract_token(request: &Request) -> Option<String> {
    // Here you can extract the token from the form body, the query string,
    // or anywhere else you like. In this simple example, we treat the entire
    // query string as the CSRF token.

    request.url.query().map(|x| x.to_owned())
}

fn index(request: &mut Request) -> IronResult<Response> {
    let token = request.extensions.get::<Csrf>().unwrap();
    let msg = format!("Hello, CSRF Token: {}", token);
    Ok(Response::with((status::Ok, msg)))
}
