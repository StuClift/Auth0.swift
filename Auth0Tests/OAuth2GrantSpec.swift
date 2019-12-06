// OAuth2GrantSpec.swift
//
// Copyright (c) 2016 Auth0 (http://auth0.com)
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

import Quick
import Nimble
import OHHTTPStubs

@testable import Auth0

class OAuth2GrantSpec: QuickSpec {

    override func spec() {
        
        let domain = URL.a0_url("samples.auth0.com")
        let authentication = Auth0Authentication(clientId: "CLIENT_ID", url: domain)
        let idToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImtleTEyMyJ9.eyJpc3MiOiJodHRwczovL3Rva2Vucy10ZXN0LmF1dGgwLmNvbS8iLCJzdWIiOiJhdXRoMHwxMjM0NTY3ODkiLCJhdWQiOlsidG9rZW5zLXRlc3QtMTIzIiwiZXh0ZXJuYWwtdGVzdC05OTkiXSwiZXhwIjoxNTc1NjYwNDg5LCJpYXQiOjE1NzU0ODc2ODksIm5vbmNlIjoiYTFiMmMzZDRlNSIsImF6cCI6InRva2Vucy10ZXN0LTEyMyIsImF1dGhfdGltZSI6MTU3NTU3NDA4OX0.Qg8r0v6cZZaZPQ1PIv6sWYCURix3zm3E5IUnlhNy_QguW_gm_FBk_DNR7AUMdwSQqWurar3yYhvCleEQVZ1sTlN33vM_xCelPf5D0vQt6VmS0o8UCV6lJV4KfVfHK8S1QeV1VVRhJz1PbT0yC0DnX0yBHE6WXWSW4d9FUYdEplC3jZZl_xVMkG7w3mKNwK3wXnYduCn8lkh88tvdK5ZUP8VqPdAOFmr_oy8_eRthsmOaoP0C6w9ayApPu4Ty9BZnIRX3T09CgD2XqM4vCfc2T_UygLhLXE6d9YoX-F3DmujFCFqmha1f4Tx_ISTbn1VlhQLz5ZPYer9ZaPIk-zRx3g"
        let nonce = "a1b2c3d4e5"

        describe("ImplicitGrant") {

            var implicit: ImplicitGrant!
            
            beforeEach {
                implicit = ImplicitGrant(authentication: authentication)
                stub(condition: isJWKSPath(domain.host!)) { _ in jwksRS256() }.name = "RS256 JWK"
            }

            it("shoud build credentials") {
                let token = UUID().uuidString
                let values = ["access_token": token, "token_type": "bearer"]
                waitUntil { done in
                    implicit.credentials(from: values) {
                        expect($0).to(haveCredentials(token))
                        done()
                    }
                }
            }

            it("shoud report error to get credentials") {
                waitUntil { done in
                    implicit.credentials(from: [:]) {
                        expect($0).to(beFailure())
                        done()
                    }
                }
            }

            it("should specify response type") {
                expect(implicit.responseType.contains(.token)).to(beTrue())
            }

            describe("ImplicitGrant with id_token") {

                beforeEach {
                    implicit = ImplicitGrant(authentication: authentication, responseType: [.idToken], nonce: nonce)
                }

                it("should build credentials") {
                    let values = ["id_token": idToken]
                    waitUntil { done in
                        implicit.credentials(from: values) {
                            expect($0).to(haveCredentials())
                            done()
                        }
                    }
                }

                it("should fail with invalid token") {
                    let idToken = "notarealtoken"
                    let values = ["id_token": idToken]
                    waitUntil { done in
                        implicit.credentials(from: values) {
                            expect($0).to(beFailure())
                            done()
                        }
                    }
                }

                it("should fail with no token") {
                    let values = ["": ""]
                    waitUntil { done in
                        implicit.credentials(from: values) {
                            expect($0).to(beFailure())
                            done()
                        }
                    }
                }

                it("should fail cause nonce does not match expected one") {
                    implicit = ImplicitGrant(authentication: authentication, responseType: [.idToken], nonce: "nomatch")
                    let values = ["id_token": idToken]
                    waitUntil { done in
                        implicit.credentials(from: values) {
                            expect($0).to(beFailure())
                            done()
                        }
                    }
                }

            }
        }


        describe("Authorization Code w/PKCE") {

            let method = "S256"
            let redirectURL = URL(string: "https://samples.auth0.com/callback")!
            var verifier: String!
            var challenge: String!
            var pkce: PKCE!
            let response: [ResponseType] = [.code]

            beforeEach {
                verifier = "\(arc4random())"
                challenge = "\(arc4random())"
                pkce = PKCE(authentication: authentication, redirectURL: redirectURL, verifier: verifier, challenge: challenge, method: method, responseType: response)
            }

            afterEach {
                OHHTTPStubs.removeAllStubs()
                stub(condition: isHost(domain.host!)) { _ in
                    return OHHTTPStubsResponse.init(error: NSError(domain: "com.auth0", code: -99999, userInfo: nil))
                    }.name = "YOU SHALL NOT PASS!"
            }

            it("shoud build credentials") {
                let token = UUID().uuidString
                let code = UUID().uuidString
                let values = ["code": code]
                stub(condition: isToken(domain.host!) && hasAtLeast(["code": code, "code_verifier": pkce.verifier, "grant_type": "authorization_code", "redirect_uri": pkce.redirectURL.absoluteString])) { _ in
                    return authResponse(accessToken: token, idToken: idToken)
                    
                }.name = "Code Exchange Auth"
                waitUntil { done in
                    pkce.credentials(from: values) {
                        expect($0).to(haveCredentials(token))
                        done()
                    }
                }
            }

            it("shoud report error to get credentials") {
                waitUntil { done in
                    pkce.credentials(from: [:]) {
                        expect($0).to(beFailure())
                        done()
                    }
                }
            }

            it("should specify response type") {
                expect(pkce.responseType.contains(.code)).to(beTrue())
            }

            it("should specify pkce parameters") {
                expect(pkce.defaults["code_challenge_method"]) == "S256"
                expect(pkce.defaults["code_challenge"]) == challenge
            }

            it("should get values from generator") {
                let generator = A0SHA256ChallengeGenerator()
                let authentication = Auth0Authentication(clientId: "CLIENT_ID", url: domain)
                pkce = PKCE(authentication: authentication, redirectURL: redirectURL, generator: generator, reponseType: response)
                
                expect(pkce.defaults["code_challenge_method"]) == generator.method
                expect(pkce.defaults["code_challenge"]) == generator.challenge
                expect(pkce.verifier) == generator.verifier
            }
        }

        describe("Authorization Code w/PKCE and idToken") {

            let domain = URL.a0_url("samples.auth0.com")
            let method = "S256"
            let redirectURL = URL(string: "https://samples.auth0.com/callback")!
            var verifier: String!
            var challenge: String!
            var pkce: PKCE!
            let response: [ResponseType] = [.code, .idToken]
            var authentication: Auth0Authentication!

            beforeEach {
                verifier = "\(arc4random())"
                challenge = "\(arc4random())"
                authentication = Auth0Authentication(clientId: "CLIENT_ID", url: domain)
                pkce = PKCE(authentication: authentication, redirectURL: redirectURL, verifier: verifier, challenge: challenge, method: method, responseType: response, nonce: nonce)
            }

            afterEach {
                OHHTTPStubs.removeAllStubs()
                stub(condition: isHost(domain.host!)) { _ in
                    return OHHTTPStubsResponse.init(error: NSError(domain: "com.auth0", code: -99999, userInfo: nil))
                    }.name = "YOU SHALL NOT PASS!"
            }

            it("shoud build credentials") {
                let token = UUID().uuidString
                let code = UUID().uuidString
                let values = ["code": code, "id_token": idToken, "nonce": nonce]
                stub(condition: isToken(domain.host!) && hasAtLeast(["code": code, "code_verifier": pkce.verifier, "grant_type": "authorization_code", "redirect_uri": pkce.redirectURL.absoluteString])) { _ in return authResponse(accessToken: token, idToken: idToken) }.name = "Code Exchange Auth"
                stub(condition: isJWKSPath(domain.host!)) { _ in jwksRS256() }.name = "RS256 JWK"
                waitUntil { done in
                    pkce.credentials(from: values) {
                        expect($0).to(haveCredentials(token))
                        done()
                    }
                }
            }

            it("shoud fail credentials no nonce") {
                pkce = PKCE(authentication: authentication, redirectURL: redirectURL, verifier: verifier, challenge: challenge, method: method, responseType: response)
                let token = UUID().uuidString
                let code = UUID().uuidString
                let values = ["code": code, "id_token" : idToken]
                stub(condition: isToken(domain.host!) && hasAtLeast(["code": code, "code_verifier": pkce.verifier, "grant_type": "authorization_code", "redirect_uri": pkce.redirectURL.absoluteString])) { _ in return authResponse(accessToken: token, idToken: idToken) }.name = "Code Exchange Auth"
                waitUntil { done in
                    pkce.credentials(from: values) {
                        expect($0).to(beFailure())
                        done()
                    }
                }
            }

            it("shoud report error to get credentials") {
                waitUntil { done in
                    pkce.credentials(from: [:]) {
                        expect($0).to(beFailure())
                        done()
                    }
                }
            }

            it("should specify response type") {
                expect(pkce.responseType.contains(.code)).to(beTrue())
                expect(pkce.responseType.contains(.idToken)).to(beTrue())
            }

            it("should specify pkce parameters") {
                expect(pkce.defaults["code_challenge_method"]) == "S256"
                expect(pkce.defaults["code_challenge"]) == challenge
            }

            it("should get values from generator") {
                let generator = A0SHA256ChallengeGenerator()
                let authentication = Auth0Authentication(clientId: "CLIENT_ID", url: domain)
                pkce = PKCE(authentication: authentication, redirectURL: redirectURL, generator: generator, reponseType: response, nonce: nonce)

                expect(pkce.defaults["code_challenge_method"]) == generator.method
                expect(pkce.defaults["code_challenge"]) == generator.challenge
                expect(pkce.verifier) == generator.verifier
            }
        }
    }
    
}
