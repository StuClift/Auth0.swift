// IDTokenValidatorContext.swift
//
// Copyright (c) 2020 Auth0 (http://auth0.com)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

import Foundation

struct IDTokenValidatorContext: IDTokenSignatureValidatorContext, IDTokenClaimsValidatorContext {
    let domain: String
    let clientId: String
    let jwksRequest: Request<JWKS, AuthenticationError>
    let nonce: String?
    let leeway: Int
    let maxAge: Int?
    
    init(domain: String,
         clientId: String,
         jwksRequest: Request<JWKS, AuthenticationError>,
         nonce: String?,
         leeway: Int,
         maxAge: Int?) {
        self.domain = domain
        self.clientId = clientId
        self.jwksRequest = jwksRequest
        self.nonce = nonce
        self.leeway = leeway
        self.maxAge = maxAge
    }
    
    init(authentication: Authentication, nonce: String?, leeway: Int, maxAge: Int?) {
        self.domain = authentication.url.host!
        self.clientId = authentication.clientId
        self.jwksRequest = authentication.jwks()
        self.nonce = nonce
        self.leeway = leeway
        self.maxAge = maxAge
    }
}