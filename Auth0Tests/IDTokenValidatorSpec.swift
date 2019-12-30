// IDTokenValidatorSpec.swift
//
// Copyright (c) 2019 Auth0 (http://auth0.com)
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
import Quick
import Nimble

@testable import Auth0

class IDTokenValidatorBaseSpec: QuickSpec {
    let domain = "tokens-test.auth0.com"
    let clientId = "tokens-test-123"
    
    // Can't override the initWithInvocation: initializer, because NSInvocation is not available in Swift
    lazy var authentication = Auth0.authentication(clientId: clientId, domain: domain)
    lazy var validatorContext = IDTokenValidatorContext(domain: domain, clientId: clientId, jwksRequest: authentication.jwks())
}

class IDTokenValidatorSpec: IDTokenValidatorBaseSpec {
    
    // Unit test cases
    //
    // Sanity checks test cases:
    /// ID Token is present
    /// ID Token is NOT present -> fail
    /// ID Token can be decoded
    /// ID Token can't be decoded -> fail
    //
    // Signature verification test cases:
    /// alg is supported --> IDTokenSignatureValidator
    /// alg is NOT supported -> fail
    /// Signature can be verified and is correct --> JWTAlgorithm.verify
    /// Signature can be verified and is NOT correct -> fail
    // Signature can't be verified and ID Token was received on a code-exchange request -> skip signature check --> Integration test
    // Signature can't be verified and ID Token was NOT received on a code-exchange request  -> skip remaining checks --> Integration test
    //
    // Claims validation test cases:
    // iss is present
    // iss is NOT present -> fail
    // iss matches the domain
    // iss does NOT match the domain -> fail
    // sub is present
    // sub is NOT present -> fail
    // aud is present
    // aud is NOT present -> fail
    // aud matches the Client ID
    // aud does NOT match the Client ID -> fail
    // aud contains the Client ID
    // aud does NOT contain the Client ID -> fail
    // exp is present
    // exp is NOT presernt -> fail
    // exp is a date in the future
    // exp is NOT a date in the future -> fail
    // iat is present
    // iat is NOT present -> fail
    // iat is a date in the past
    // iat is NOT a date in the past -> fail
    // nonce is present
    // nonce is NOT present -> fail
    // nonce matches the one in the request
    // nonce does NOT match the one in the request -> fail
    // aud is an array with 1+ element and azp is present
    // aud is an array with 1+ element and azp is NOT present -> fail
    // aud is an array with 1+ element and azp matches the Client ID
    // aud is an array with 1+ element and azp does NOT match the Client ID -> fail
    // max_age was included in the request and auth_time is present
    // max_age was included in the request and auth_time is NOT present -> fail
    // max_age was included in the request and (auth_time + max_age + leeway) is a date in the future
    // max_age was included in the request and (auth_time + max_age + leeway) is NOT a date in the future -> fail

    override func spec() {
        let validatorContext = self.validatorContext
        let mockSignatureValidator = MockIDTokenSignatureValidator()
        let mockClaimsValidator = MockIDTokenClaimsValidator()
        
        describe("sanity checks") {
            it("should fail to validate a nil id token") {
                waitUntil { done in
                    validate(idToken: nil,
                             context: validatorContext,
                             signatureValidator: mockSignatureValidator,
                             claimsValidator: mockClaimsValidator) { error in
                        expect(error as? IDTokenValidationError).to(equal(IDTokenValidationError.missingToken))
                        done()
                    }
                }
            }
            
            it("should fail to decode an empty id token") {
                waitUntil { done in
                    validate(idToken: "",
                             context: validatorContext,
                             signatureValidator: mockSignatureValidator,
                             claimsValidator: mockClaimsValidator) { error in
                        expect(error as? IDTokenValidationError).to(equal(IDTokenValidationError.cannotDecode))
                        done()
                    }
                }
            }
            
            it("should fail to decode a malformed id token") {
                waitUntil { done in
                    validate(idToken: "a.b.c.d.e",
                             context: validatorContext,
                             signatureValidator: mockSignatureValidator,
                             claimsValidator: mockClaimsValidator) { error in
                        expect(error as? IDTokenValidationError).to(equal(IDTokenValidationError.cannotDecode))
                        done()
                    }
                }
                
                waitUntil { done in
                    validate(idToken: "a.b.",
                             context: validatorContext,
                             signatureValidator: mockSignatureValidator,
                             claimsValidator: mockClaimsValidator) { error in
                        expect(error as? IDTokenValidationError).to(equal(IDTokenValidationError.cannotDecode))
                        done()
                    }
                }
            }
            
            it("should fail to decode an id token that's missing the signature") {
                waitUntil { done in
                    validate(idToken: "a.b",
                             context: validatorContext,
                             signatureValidator: mockSignatureValidator,
                             claimsValidator: mockClaimsValidator) { error in
                        expect(error as? IDTokenValidationError).to(equal(IDTokenValidationError.cannotDecode))
                        done()
                    }
                }
            }
        }
    }
    
}
