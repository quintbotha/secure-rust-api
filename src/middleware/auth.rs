use crate::utils::auth::decode_jwt;
use actix_web::{
    body::{BoxBody, EitherBody},
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpMessage,
};
use futures_util::future::LocalBoxFuture;
use std::future::{ready, Ready};

pub struct AuthMiddleware;

impl<S, B> Transform<S, ServiceRequest> for AuthMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;
    type Error = Error;
    type InitError = ();
    type Transform = AuthMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AuthMiddlewareService { service }))
    }
}

pub struct AuthMiddlewareService<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for AuthMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        // Extract Authorization header
        let auth_header = req.headers().get("Authorization");

        let token = match auth_header {
            Some(header_value) => match header_value.to_str() {
                Ok(header_str) => header_str.strip_prefix("Bearer ").map(|s| s.to_string()),
                Err(_) => None,
            },
            None => None,
        };

        // Validate token
        let claims = match token {
            Some(t) => match decode_jwt(&t) {
                Ok(claims) => claims,
                Err(_) => {
                    let (req, _pl) = req.into_parts();
                    let res = actix_web::HttpResponse::Unauthorized().json(serde_json::json!({
                        "error": "Invalid or expired token"
                    }));
                    return Box::pin(async move {
                        Ok(ServiceResponse::new(req, res).map_into_right_body())
                    });
                }
            },
            None => {
                let (req, _pl) = req.into_parts();
                let res = actix_web::HttpResponse::Unauthorized().json(serde_json::json!({
                    "error": "Authorization token required"
                }));
                return Box::pin(async move {
                    Ok(ServiceResponse::new(req, res).map_into_right_body())
                });
            }
        };

        // Insert claims into request extensions
        req.extensions_mut().insert(claims);

        let fut = self.service.call(req);
        Box::pin(async move {
            let res = fut.await?;
            Ok(res.map_into_left_body())
        })
    }
}
