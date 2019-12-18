//
//  IDTokenValidatorSpec.swift
//  Auth0
//
//  Created by Rita Zerrizuela on 02/12/2019.
//  Copyright © 2019 Auth0. All rights reserved.
//

import Foundation
import Quick
import Nimble
import OHHTTPStubs
import JWTDecode

@testable import Auth0

struct IDTokenFixtures {
    struct valid {
        struct signature {
            static let rs256 = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImtleTEyMyJ9.eyJpc3MiOiJodHRwczovL3Rva2Vucy10ZXN0LmF1dGgwLmNvbS8iLCJzdWIiOiJhdXRoMHwxMjM0NTY3ODkiLCJhdWQiOlsidG9rZW5zLXRlc3QtMTIzIiwiZXh0ZXJuYWwtdGVzdC05OTkiXSwiZXhwIjoxNTc2NzgxNjYyLCJpYXQiOjE1NzY2MDg4NjIsIm5vbmNlIjoiYTFiMmMzZDRlNSIsImF6cCI6InRva2Vucy10ZXN0LTEyMyIsImF1dGhfdGltZSI6MTU3NjY5NTI2Mn0.i_TYzZXqIMCUGC8F6gH9LvZXQoW0nZR4_nGKisKWVWlPY-y28odtQFekYfrYhjSm-c1-UAoQahUIhGT8UvwtH4so3SRgOyRHiMlm531CnJlL1ybP2ihC57AuQSb1Xt9x614a26UuoXUOuDrc7IVPyGWXGyWrakpMZIZ8YPBXZpjzOcKg9Z2jqg9n_RRSBzuskscXAEYORouQvHW__0nez8KSy3SCMYyohBlI5fscm3GpABFYnZMzNClrL47izbZ8KgdmKXNj-Ej2edTGyiX4-sj7g-momN2HcfJ7b7TeUzMqLGdfbi-fyGG6Fv7pmIglbTShgUip08ucNOTgD-bSOg"
        }
        
        struct claims {}
    }
    
    struct invalid {
        struct format {
            static let empty = ""
            static let tooLong = "a.b.c.d.e"
            static let tooShort = "a.b."
            static let missingSignature = "a.b"
        }
        
        struct signature {
            static let rs256 = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImtleTEyMyJ9.eyJpc3MiOiJodHRwczovL3Rva2Vucy10ZXN0LmF1dGgwLmNvbS8iLCJzdWIiOiJhdXRoMHwxMjM0NTY3ODkiLCJhdWQiOlsidG9rZW5zLXRlc3QtMTIzIiwiZXh0ZXJuYWwtdGVzdC05OTkiXSwiZXhwIjoxNTc2NzgxNjYyLCJpYXQiOjE1NzY2MDg4NjIsIm5vbmNlIjoiYTFiMmMzZDRlNSIsImF6cCI6InRva2Vucy10ZXN0LTEyMyIsImF1dGhfdGltZSI6MTU3NjY5NTI2Mn0.invalidsignature"
            static let unsupportedAlgorithm = "eyJhbGciOiJub25lIiwia2lkIjoia2V5MTIzIn0.eyJpc3MiOiJodHRwczovL3Rva2Vucy10ZXN0LmF1dGgwLmNvbS8iLCJzdWIiOiJhdXRoMHwxMjM0NTY3ODkiLCJhdWQiOlsidG9rZW5zLXRlc3QtMTIzIiwiZXh0ZXJuYWwtdGVzdC05OTkiXSwiZXhwIjoxNTc2NzgxNjYyLCJpYXQiOjE1NzY2MDg4NjIsIm5vbmNlIjoiYTFiMmMzZDRlNSIsImF6cCI6InRva2Vucy10ZXN0LTEyMyIsImF1dGhfdGltZSI6MTU3NjY5NTI2Mn0."
        }
        
        struct claims {}
    }
}

class IDTokenValidatorSpec: QuickSpec {
    
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
        let domain = "tokens-test.auth0.com"
        let clientId = "tokens-test-123"
        let jwk = JWK(keyType: "RS",
                      keyId: JWKKid,
                      usage: nil,
                      algorithm: "RS256",
                      certUrl: nil,
                      certThumbprint: nil,
                      certChain: nil,
                      rsaModulus: JWKRSAModulus,
                      rsaExponent: JWKRSAExponent)
        
        let authentication = Auth0.authentication(clientId: clientId, domain: domain)
        let validatorContext = IDTokenValidatorContext(domain: domain, clientId: clientId, jwksRequest: authentication.jwks())
        
        describe("sanity checks") {
            let mockSignatureValidator = MockIDTokenSignatureValidator()
            let mockClaimsValidator = MockIDTokenClaimsValidator()
            
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
                    validate(idToken: IDTokenFixtures.invalid.format.empty,
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
                    validate(idToken: IDTokenFixtures.invalid.format.tooLong,
                             context: validatorContext,
                             signatureValidator: mockSignatureValidator,
                             claimsValidator: mockClaimsValidator) { error in
                        expect(error as? IDTokenValidationError).to(equal(IDTokenValidationError.cannotDecode))
                        done()
                    }
                }
                
                waitUntil { done in
                    validate(idToken: IDTokenFixtures.invalid.format.tooShort,
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
                    validate(idToken: IDTokenFixtures.invalid.format.missingSignature,
                             context: validatorContext,
                             signatureValidator: mockSignatureValidator,
                             claimsValidator: mockClaimsValidator) { error in
                        expect(error as? IDTokenValidationError).to(equal(IDTokenValidationError.cannotDecode))
                        done()
                    }
                }
            }
        }
        
        describe("signature validation") {
            let signatureValidator = IDTokenSignatureValidator(context: validatorContext)
            
            beforeEach {
                stub(condition: isJWKSPath(domain)) { _ in jwksRS256() }.name = "RS256 JWK"
            }
            
            context("algorithm support") {
                it("should support RSA256") {
                    let jwt = try! decode(jwt: IDTokenFixtures.valid.signature.rs256)
                    
                    waitUntil { done in
                        signatureValidator.validate(jwt) { error in
                            expect(error).to(beNil())
                            done()
                        }
                    }
                }

                it("should not support other algorithms") {
                    let jwt = try! decode(jwt: IDTokenFixtures.invalid.signature.unsupportedAlgorithm)
                    
                    waitUntil { done in
                        signatureValidator.validate(jwt) { error in
                            let expectedError = IDTokenSignatureValidator.ValidationError.invalidAlgorithm(actual: "", expected: "")
                            
                            expect(error as? IDTokenSignatureValidator.ValidationError).to(equal(expectedError))
                            done()
                        }
                    }
                }
            }
            
            it("should pass with a correct RS256 signature") {
                let jwt = try! decode(jwt: IDTokenFixtures.valid.signature.rs256)
                
                expect(JWTAlgorithm.rs256.verify(jwt, using: jwk)).to(beTrue())
            }
            
            it("should fail with an incorrect RS256 signature") {
                let jwt = try! decode(jwt: IDTokenFixtures.invalid.signature.rs256)

                expect(JWTAlgorithm.rs256.verify(jwt, using: jwk)).to(beFalse())
            }
        }
    }
    
}

class MockIDTokenSignatureValidator: JWTSignatureValidator {
    func validate(_ jwt: JWT, callback: @escaping (LocalizedError?) -> Void) {
        callback(nil)
    }
}

class MockIDTokenClaimsValidator: JWTClaimsValidator {
    func validate(_ jwt: JWT) -> LocalizedError? {
        return nil
    }
}
