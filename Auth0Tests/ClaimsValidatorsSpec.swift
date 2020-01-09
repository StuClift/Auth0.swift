// ClaimsValidatorsSpec.swift
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
import Quick
import Nimble
import OHHTTPStubs

@testable import Auth0

class ClaimsValidatorsSpec: IDTokenValidatorBaseSpec {
    
    override func spec() {
        
        describe("claims validation") {
            
            let jwt = generateJWT()
            
            context("successful validation") {
                it("should return nil if no claim validator returns an error") {
                    let claimsValidators: [JWTClaimValidator] = [MockSuccessfulIDTokenClaimValidator(),
                                                                 MockSuccessfulIDTokenClaimValidator(),
                                                                 MockSuccessfulIDTokenClaimValidator()]
                    let claimsValidator = IDTokenClaimsValidator(validators: claimsValidators)
                    
                    expect(claimsValidator.validate(jwt)).to(beNil())
                }
            }
            
            context("unsuccessful validation") {
                it("should return an error if a validation fails") {
                    let claimsValidators: [JWTClaimValidator] = [MockSuccessfulIDTokenClaimValidator(),
                                                                 MockSuccessfulIDTokenClaimValidator(),
                                                                 MockSuccessfulIDTokenClaimValidator(),
                                                                 MockUnsuccessfulIDTokenClaimValidator()]
                    let claimsValidator = IDTokenClaimsValidator(validators: claimsValidators)
                    
                    expect(claimsValidator.validate(jwt)).toNot(beNil())
                }
                
                it("should return the error from the first failed validation") {
                    let claimsValidators: [JWTClaimValidator] = [MockSuccessfulIDTokenClaimValidator(),
                                                                 MockUnsuccessfulIDTokenClaimValidator(errorCase: .errorCase2),
                                                                 MockSuccessfulIDTokenClaimValidator(),
                                                                 MockUnsuccessfulIDTokenClaimValidator(errorCase: .errorCase1)]
                    let claimsValidator = IDTokenClaimsValidator(validators: claimsValidators)
                    let expectedError = MockUnsuccessfulIDTokenClaimValidator.ValidationError.errorCase2
                    
                    expect(claimsValidator.validate(jwt)).to(matchError(expectedError))
                }
                
                it("should not execute further validations past the one that failed") {
                    let firstSpyClaimValidator = SpyUnsuccessfulIDTokenClaimValidator()
                    let secondSpyClaimValidator = SpyUnsuccessfulIDTokenClaimValidator()
                    let claimsValidators: [JWTClaimValidator] = [MockSuccessfulIDTokenClaimValidator(),
                                                                 firstSpyClaimValidator,
                                                                 secondSpyClaimValidator,
                                                                 MockSuccessfulIDTokenClaimValidator()]
                    let claimsValidator = IDTokenClaimsValidator(validators: claimsValidators)
                    
                    _ = claimsValidator.validate(jwt)
                    
                    expect(firstSpyClaimValidator.didExecuteValidation).to(beTrue())
                    expect(secondSpyClaimValidator.didExecuteValidation).to(beFalse())
                }
            }
        }
        
        describe("iss validation") {
            
            var issValidator: IDTokenIssValidator!
            let domain = self.domain
            
            beforeEach {
                issValidator = IDTokenIssValidator(domain: domain)
            }
            
            context("missing iss") {
                it("should return nil if iss is present") {
                    let jwt = generateJWT(iss: URL.a0_url(domain).absoluteString)
                    
                    expect(issValidator.validate(jwt)).to(beNil())
                }
                
                it("should return an error if iss is missing") {
                    let jwt = generateJWT(iss: nil)
                    let expectedError = IDTokenIssValidator.ValidationError.missingIss
                    
                    expect(issValidator.validate(jwt)).to(matchError(expectedError))
                }
            }
            
            context("mismatched iss") {
                it("should return nil if iss matches the domain") {
                    let jwt = generateJWT(iss: URL.a0_url(domain).absoluteString)
                    
                    expect(issValidator.validate(jwt)).to(beNil())
                }
                
                it("should return an error if iss does not match the domain") {
                    let jwt = generateJWT(iss: "https://samples.auth0.com")
                    let expectedError = IDTokenIssValidator.ValidationError.mismatchedIss(actual: "", expected: "")
                    
                    expect(issValidator.validate(jwt)).to(matchError(expectedError))
                }
            }
        }
        
        describe("sub validation") {
            
            var subValidator: IDTokenSubValidator!
            
            beforeEach {
                subValidator = IDTokenSubValidator()
            }
            
            context("missing sub") {
                it("should return nil if sub is present") {
                    let jwt = generateJWT(sub: "user123")
                    
                    expect(subValidator.validate(jwt)).to(beNil())
                }
                
                it("should return an error if sub is missing") {
                    let jwt = generateJWT(sub: nil)
                    let expectedError = IDTokenSubValidator.ValidationError.missingSub
                    
                    expect((subValidator.validate(jwt) as! IDTokenSubValidator.ValidationError)).to(equal(expectedError))
                }
            }
        }
        
        describe("aud validation") {
            
            var audValidator: IDTokenAudValidator!
            let clientId = self.clientId
            
            beforeEach {
                audValidator = IDTokenAudValidator(clientId: clientId)
            }
            
            context("missing aud") {
                it("should return nil if aud is present") {
                    let jwt = generateJWT(aud: [clientId])
                    
                    expect(audValidator.validate(jwt)).to(beNil())
                }
                
                it("should return an error if aud is missing") {
                    let jwt = generateJWT(aud: nil)
                    let expectedError = IDTokenAudValidator.ValidationError.missingAud
                    
                    expect(audValidator.validate(jwt)).to(matchError(expectedError))
                }
            }
            
            context("mismatched aud (string)") {
                it("should return nil if aud matches the client id") {
                    let jwt = generateJWT(aud: [clientId])
                    
                    expect(audValidator.validate(jwt)).to(beNil())
                }
                
                it("should return an error if aud does not match the client id") {
                    let jwt = generateJWT(aud: ["https://example.com"])
                    let expectedError = IDTokenAudValidator.ValidationError.mismatchedAudString(actual: "", expected: "")
                    
                    expect(audValidator.validate(jwt)).to(matchError(expectedError))
                }
            }
            
            context("mismatched aud (array)") {
                it("should return nil if aud matches the client id") {
                    let jwt = generateJWT(aud: ["https://example.com", "https://example.net", "https://example.org", clientId])
                    
                    expect(audValidator.validate(jwt)).to(beNil())
                }
                
                it("should return an error if aud does not match the client id") {
                    let jwt = generateJWT(aud: ["https://example.com", "https://example.net", "https://example.org"])
                    let expectedError = IDTokenAudValidator.ValidationError.mismatchedAudArray(actual: "", expected: "")
                    
                    expect(audValidator.validate(jwt)).to(matchError(expectedError))
                }
            }
        }
        
        describe("exp validation") {
            
            var expValidator: IDTokenExpValidator!
            let leeway = self.leeway
            
            beforeEach {
                expValidator = IDTokenExpValidator(leeway: leeway)
            }
            
            context("missing exp") {
                it("should return nil if exp is present") {
                    let jwt = generateJWT(exp: Date().addingTimeInterval(100 + Double(leeway)))
                    
                    expect(expValidator.validate(jwt)).to(beNil())
                }
                
                it("should return an error if exp is missing") {
                    let jwt = generateJWT(exp: nil)
                    let expectedError = IDTokenExpValidator.ValidationError.missingExp
                    
                    expect(expValidator.validate(jwt)).to(matchError(expectedError))
                }
            }
            
            context("past exp") {
                it("should return nil if exp in the future") {
                    let jwt = generateJWT(exp: Date().addingTimeInterval(100 + Double(leeway)))
                    
                    expect(expValidator.validate(jwt)).to(beNil())
                }
                
                it("should return an error if exp is in the past") {
                    let jwt = generateJWT(exp: Date().addingTimeInterval(-100 - Double(leeway)))
                    let expectedError = IDTokenExpValidator.ValidationError.pastExp(currentTime: 0, expirationTime: 0)
                    
                    expect(expValidator.validate(jwt)).to(matchError(expectedError))
                }
            }
        }
        
        describe("iat validation") {
            
            var iatValidator: IDTokenIatValidator!
            
            beforeEach {
                iatValidator = IDTokenIatValidator()
            }
            
            context("missing iat") {
                it("should return nil if iat is present") {
                    let jwt = generateJWT(iat: Date())
                    
                    expect(iatValidator.validate(jwt)).to(beNil())
                }
                
                it("should return an error if iat is missing") {
                    let jwt = generateJWT(iat: nil)
                    let expectedError = IDTokenIatValidator.ValidationError.missingIat
                    
                    expect(iatValidator.validate(jwt)).to(matchError(expectedError))
                }
            }
        }
        
        describe("nonce validation") {
            
            var nonceValidator: IDTokenNonceValidator!
            let nonce = self.nonce
            
            beforeEach {
                nonceValidator = IDTokenNonceValidator(nonce: nonce)
            }
            
            context("missing nonce") {
                it("should return nil if nonce is present") {
                    let jwt = generateJWT(nonce: nonce)
                    
                    expect(nonceValidator.validate(jwt)).to(beNil())
                }
                
                it("should return an error if nonce is missing") {
                    let jwt = generateJWT(nonce: nil)
                    let expectedError = IDTokenNonceValidator.ValidationError.missingNonce
                    
                    expect(nonceValidator.validate(jwt)).to(matchError(expectedError))
                }
            }
            
            context("mismatched nonce") {
                it("should return nil if nonce matches the request nonce") {
                    let jwt = generateJWT(nonce: nonce)
                    
                    expect(nonceValidator.validate(jwt)).to(beNil())
                }
                
                it("should return an error if nonce does not match the request nonce") {
                    let jwt = generateJWT(nonce: "abc123")
                    let expectedError = IDTokenNonceValidator.ValidationError.mismatchedNonce(actual: "", expected: "")
                    
                    expect(nonceValidator.validate(jwt)).to(matchError(expectedError))
                }
            }
        }
        
        describe("azp validation") {
            
            var azpValidator: IDTokenAzpValidator!
            let clientId = self.clientId
            
            beforeEach {
                azpValidator = IDTokenAzpValidator(clientId: clientId)
            }
            
            context("missing azp") {
                it("should return nil if azp is present") {
                    let jwt = generateJWT(aud: ["https://example.com", "https://example.net", "https://example.org"], azp: clientId)
                    
                    expect(azpValidator.validate(jwt)).to(beNil())
                }
                
                it("should return an error if azp is missing") {
                    let jwt = generateJWT(aud: nil)
                    let expectedError = IDTokenAzpValidator.ValidationError.missingAzp
                    
                    expect(azpValidator.validate(jwt)).to(matchError(expectedError))
                }
            }
            
            context("mismatched azp") {
                it("should return nil if azp matches the client id") {
                    let jwt = generateJWT(aud: ["https://example.com", "https://example.net", "https://example.org"], azp: clientId)
                    
                    expect(azpValidator.validate(jwt)).to(beNil())
                }
                
                it("should return an error if azp does not match the client id") {
                    let jwt = generateJWT(aud: ["https://example.com", "https://example.net", "https://example.org"], azp: "abc123")
                    let expectedError = IDTokenAzpValidator.ValidationError.mismatchedAzp(actual: "", expected: "")
                    
                    expect(azpValidator.validate(jwt)).to(matchError(expectedError))
                }
            }
        }
        
        describe("auth time validation") {
            
            var authTimeValidator: IDTokenAuthTimeValidator!
            let leeway = self.leeway
            let maxAge = self.leeway
            
            beforeEach {
                authTimeValidator = IDTokenAuthTimeValidator(leeway: leeway, maxAge: maxAge)
            }
            
            context("missing auth time") {
                it("should return nil if max age is present and auth time is present") {
                    let jwt = generateJWT(maxAge: maxAge, authTime: Date().addingTimeInterval(-100 - Double(leeway) - Double(maxAge)))
                    
                    expect(authTimeValidator.validate(jwt)).to(beNil())
                }
                
                it("should return an error if max age is present and auth time is missing") {
                    let jwt = generateJWT(maxAge: maxAge, authTime: nil)
                    let expectedError = IDTokenAuthTimeValidator.ValidationError.missingAuthTime
                    
                    expect(authTimeValidator.validate(jwt)).to(matchError(expectedError))
                }
            }
            
            context("future last auth time") {
                it("should return nil if last auth time is in the past") {
                    let jwt = generateJWT(maxAge: maxAge, authTime: Date().addingTimeInterval(-100 - Double(leeway) - Double(maxAge)))
                    
                    expect(authTimeValidator.validate(jwt)).to(beNil())
                }
                
                it("should return an error if last auth time is in the future") {
                    let jwt = generateJWT(maxAge: maxAge, authTime: Date().addingTimeInterval(100 + Double(leeway) + Double(maxAge)))
                    let expectedError = IDTokenAuthTimeValidator.ValidationError.pastLastAuth(currentTime: 0, lastAuthTime: 0)
                    
                    expect(authTimeValidator.validate(jwt)).to(matchError(expectedError))
                }
            }
        }
        
    }
    
}