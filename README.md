Iron Double Submit Cookie Cross-Site Request Forgery
====================================================

[![Build Status](https://secure.travis-ci.org/tecywiz121/iron-dsc-csrf.svg?branch=master)](https://travis-ci.org/tecywiz121/iron-dsc-csrf/)
[![Crates.io Status](http://meritbadge.herokuapp.com/iron-dsc-csrf)](https://crates.io/crates/iron-dsc-csrf)
[![Documentation](https://docs.rs/iron-dsc-csrf/badge.svg)](https://docs.rs/iron-dsc-csrf)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/tecywiz121/iron-dsc-csrf/master/LICENSE)

> Iron middleware providing CSRF protection.

## Usage Example

```rust
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
```

## Overview

`iron-dsc-csrf` is an Iron middleware that provides protection against Cross-Site
Request Forgery attacks. For more information on CSRF attacks, see [OWASP][0]'s,
and [Wikipedia][1]'s articles.

This middleware uses an approach called Double Submit Cookie, where a random
token is generated and stored client-side in a cookie. Any time an unsafe HTTP
method (ex. `POST`, `PUT`, etc) is used, the submission must also include the
token from the cookie. OWASP has a more detailed [description][2].

[0]: https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)
[1]: https://en.wikipedia.org/wiki/Cross-site_request_forgery
[2]: https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet#Double_Submit_Cookie
