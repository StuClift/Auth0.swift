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

fileprivate enum TokenFormatFixtures: String {
    case empty = ""
    case invalidFormat1 = "a.b.c.d.e"
    case invalidFormat2 = "a.b."
    case missingSignature = "a.b"
}

fileprivate enum TokenSignatureFixtures: String {
    case validRS256 = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImtleTEyMyJ9.eyJpc3MiOiJodHRwczovL3Rva2Vucy10ZXN0LmF1dGgwLmNvbS8iLCJzdWIiOiJhdXRoMHwxMjM0NTY3ODkiLCJhdWQiOlsidG9rZW5zLXRlc3QtMTIzIiwiZXh0ZXJuYWwtdGVzdC05OTkiXSwiZXhwIjoxNTc1NjYwNDg5LCJpYXQiOjE1NzU0ODc2ODksIm5vbmNlIjoiYTFiMmMzZDRlNSIsImF6cCI6InRva2Vucy10ZXN0LTEyMyIsImF1dGhfdGltZSI6MTU3NTU3NDA4OX0.Qg8r0v6cZZaZPQ1PIv6sWYCURix3zm3E5IUnlhNy_QguW_gm_FBk_DNR7AUMdwSQqWurar3yYhvCleEQVZ1sTlN33vM_xCelPf5D0vQt6VmS0o8UCV6lJV4KfVfHK8S1QeV1VVRhJz1PbT0yC0DnX0yBHE6WXWSW4d9FUYdEplC3jZZl_xVMkG7w3mKNwK3wXnYduCn8lkh88tvdK5ZUP8VqPdAOFmr_oy8_eRthsmOaoP0C6w9ayApPu4Ty9BZnIRX3T09CgD2XqM4vCfc2T_UygLhLXE6d9YoX-F3DmujFCFqmha1f4Tx_ISTbn1VlhQLz5ZPYer9ZaPIk-zRx3g"
    case invalidRS256 = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImtleTEyMyJ9.eyJpc3MiOiJodHRwczovL3Rva2Vucy10ZXN0LmF1dGgwLmNvbS8iLCJzdWIiOiJhdXRoMHwxMjM0NTY3ODkiLCJhdWQiOlsidG9rZW5zLXRlc3QtMTIzIiwiZXh0ZXJuYWwtdGVzdC05OTkiXSwiZXhwIjoxNTc1NjYwNDg5LCJpYXQiOjE1NzU0ODc2ODksIm5vbmNlIjoiYTFiMmMzZDRlNSIsImF6cCI6InRva2Vucy10ZXN0LTEyMyIsImF1dGhfdGltZSI6MTU3NTU3NDA4OX0.invalidsignature"
    case unsupportedAlgorithm = "eyJhbGciOiJub25lIiwia2lkIjoia2V5MTIzIn0.eyJpc3MiOiJodHRwczovL3Rva2Vucy10ZXN0LmF1dGgwLmNvbS8iLCJzdWIiOiJhdXRoMHwxMjM0NTY3ODkiLCJhdWQiOlsidG9rZW5zLXRlc3QtMTIzIiwiZXh0ZXJuYWwtdGVzdC05OTkiXSwiZXhwIjoxNTc1NjYwNDg5LCJpYXQiOjE1NzU0ODc2ODksIm5vbmNlIjoiYTFiMmMzZDRlNSIsImF6cCI6InRva2Vucy10ZXN0LTEyMyIsImF1dGhfdGltZSI6MTU3NTU3NDA4OX0."
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
        let authentication = Auth0.authentication(clientId: clientId, domain: domain)
        let validatorContext = IDTokenValidatorContext(domain: domain, clientId: clientId, jwksRequest: authentication.jwks())
        let signatureValidator = IDTokenSignatureValidator(context: validatorContext)
        let jwk = JWK(keyType: "RS",
                      keyId: JWKKid,
                      usage: nil,
                      algorithm: "RS256",
                      certUrl: nil,
                      certThumbprint: nil,
                      certChain: nil,
                      rsaModulus: JWKRSAModulus,
                      rsaExponent: JWKRSAExponent)
        
        describe("sanity checks") {
            it("should fail to validate a nil id token") {
                waitUntil { done in
                    validate(idToken: nil, context: validatorContext) { error in
                        expect(error as? IDTokenValidationError).to(equal(IDTokenValidationError.missingToken))
                        done()
                    }
                }
            }
            
            it("should fail to decode an empty id token") {
                waitUntil { done in
                    validate(idToken: TokenFormatFixtures.empty.rawValue, context: validatorContext) { error in
                        expect(error as? IDTokenValidationError).to(equal(IDTokenValidationError.cannotDecode))
                        done()
                    }
                }
            }
            
            it("should fail to decode a malformed id token") {
                waitUntil { done in
                    validate(idToken: TokenFormatFixtures.invalidFormat1.rawValue, context: validatorContext) { error in
                        expect(error as? IDTokenValidationError).to(equal(IDTokenValidationError.cannotDecode))
                        done()
                    }
                }
                
                waitUntil { done in
                    validate(idToken: TokenFormatFixtures.invalidFormat2.rawValue, context: validatorContext) { error in
                        expect(error as? IDTokenValidationError).to(equal(IDTokenValidationError.cannotDecode))
                        done()
                    }
                }
            }
            
            it("should fail to decode an id token that's missing the signature") {
                waitUntil { done in
                    validate(idToken: TokenFormatFixtures.missingSignature.rawValue, context: validatorContext) { error in
                        expect(error as? IDTokenValidationError).to(equal(IDTokenValidationError.cannotDecode))
                        done()
                    }
                }
            }
        }
        
        describe("signature validation") {
            context("algorithm support") {
                it("should support RSA256") {
                    let jwt = try! decode(jwt: TokenSignatureFixtures.validRS256.rawValue)
                    
                    stub(condition: isJWKSPath(domain)) { _ in jwksRS256() }.name = "RS256 JWK"
                    
                    waitUntil { done in
                        signatureValidator.validate(jwt) { error in
                            expect(error).to(beNil())
                            done()
                        }
                    }
                }

                it("should not support other algorithms") {
                    let jwt = try! decode(jwt: TokenSignatureFixtures.unsupportedAlgorithm.rawValue)
                    
                    stub(condition: isJWKSPath(domain)) { _ in jwksUnsupported() }.name = "Unsupported JWK Algorithm"

                    waitUntil { done in
                        signatureValidator.validate(jwt) { error in
                            expect(error as? IDTokenSignatureValidator.ValidationError).to(equal(IDTokenSignatureValidator.ValidationError.invalidAlgorithm(actual: "", expected: "")))
                            done()
                        }
                    }
                }
            }
            
            it("should pass with a correct RS256 signature") {
                let jwt = try! decode(jwt: TokenSignatureFixtures.validRS256.rawValue)
                
                expect(JWTAlgorithm.rs256.verify(jwt, using: jwk)).to(beTrue())
            }
            
            it("should fail with an incorrect RS256 signature") {
                let jwt = try! decode(jwt: TokenSignatureFixtures.invalidRS256.rawValue)

                expect(JWTAlgorithm.rs256.verify(jwt, using: jwk)).to(beFalse())
            }
        }
    }
    
}
