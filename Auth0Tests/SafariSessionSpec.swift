// SafariSessionSpec.swift
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
import SafariServices
import OHHTTPStubs

@testable import Auth0

private let ClientId = "CLIENT_ID"
private let Domain = URL(string: "https://samples.auth0.com")!

class MockSafariViewController: SFSafariViewController {
    var presenting: UIViewController? = nil

    override var presentingViewController: UIViewController? {
        return presenting ?? super.presentingViewController
    }
}

private let RedirectURL = URL(string: "https://samples.auth0.com/callback")!

class SafariSessionSpec: QuickSpec {

    override func spec() {

        var result: Result<Credentials>? = nil
        let callback: (Result<Credentials>) -> () = { result = $0 }
        let controller = MockSafariViewController(url: URL(string: "https://auth0.com")!)
        let domain = URL.a0_url("samples.auth0.com")
        let authentication = Auth0Authentication(clientId: "CLIENT_ID", url: domain)
        let handler = ImplicitGrant(authentication: authentication)
        let session = SafariSession(controller: controller, redirectURL: RedirectURL, handler: handler, finish: callback, logger: nil)

        beforeEach {
            result = nil
        }

        context("SFSafariViewControllerDelegate") {
            var session: SafariSession!

            beforeEach {
                controller.delegate = nil
                session = SafariSession(controller: controller, redirectURL: RedirectURL, handler: handler, finish: callback, logger: nil)
            }

            it("should set itself as delegate") {
                expect(controller.delegate).toNot(beNil())
            }

            it("should send cancelled event") {
                session.safariViewControllerDidFinish(controller)
                expect(result).toEventually(beFailure())
            }
        }

        describe("resume:options") {

            beforeEach {
                controller.presenting = MockViewController()
            }

            it("should return true if URL matches redirect URL") {
                expect(session.resume(URL(string: "https://samples.auth0.com/callback?access_token=ATOKEN&token_type=bearer")!)).to(beTrue())
            }

            it("should return false when URL does not match redirect URL") {
                expect(session.resume(URL(string: "https://auth0.com/mobile?access_token=ATOKEN&token_type=bearer")!)).to(beFalse())
            }

            context("response_type=token") {
                
                let session = SafariSession(controller: controller, redirectURL: RedirectURL, handler: handler, finish: callback, logger: nil)

                it("should not return credentials from query string") {
                    let _ = session.resume(URL(string: "https://samples.auth0.com/callback?access_token=ATOKEN&token_type=bearer")!)
                    expect(result).toEventuallyNot(haveCredentials())
                }

                it("should return credentials from fragment") {
                    let _ = session.resume(URL(string: "https://samples.auth0.com/callback#access_token=ATOKEN&token_type=bearer")!)
                    expect(result).toEventually(haveCredentials())
                }

                it("should not return error from query string") {
                    let _ = session.resume(URL(string: "https://samples.auth0.com/callback?error=error&error_description=description")!)
                    expect(result).toEventuallyNot(haveAuthenticationError(code: "error", description: "description"))
                }

                it("should return error from fragment") {
                    let _ = session.resume(URL(string: "https://samples.auth0.com/callback#error=error&error_description=description")!)
                    expect(result).toEventually(haveAuthenticationError(code: "error", description: "description"))
                }

            }

            context("response_type=code") {

                let generator = A0SHA256ChallengeGenerator()
                let session = SafariSession(controller: controller, redirectURL: RedirectURL, handler: PKCE(authentication: Auth0Authentication(clientId: ClientId, url: Domain), redirectURL: RedirectURL, generator: generator, reponseType: [.code]), finish: callback, logger: nil)
                let code = "123456"
                let domain = "samples.auth0.com"

                beforeEach {
                    stub(condition: isToken(domain) && hasAtLeast(["code": code, "code_verifier": generator.verifier, "grant_type": "authorization_code", "redirect_uri": RedirectURL.absoluteString])) {
                        _ in return authResponse(accessToken: "AT",
                                                 idToken: "eyJhbGciOiJSUzI1NiIsImtpZCI6ImtleTEyMyJ9.eyJpc3MiOiJodHRwczovL3Rva2Vucy10ZXN0LmF1dGgwLmNvbS8iLCJzdWIiOiJhdXRoMHwxMjM0NTY3ODkiLCJhdWQiOlsidG9rZW5zLXRlc3QtMTIzIiwiZXh0ZXJuYWwtdGVzdC05OTkiXSwiZXhwIjoxNTc1NjYwNDg5LCJpYXQiOjE1NzU0ODc2ODksIm5vbmNlIjoiYTFiMmMzZDRlNSIsImF6cCI6InRva2Vucy10ZXN0LTEyMyIsImF1dGhfdGltZSI6MTU3NTU3NDA4OX0.Qg8r0v6cZZaZPQ1PIv6sWYCURix3zm3E5IUnlhNy_QguW_gm_FBk_DNR7AUMdwSQqWurar3yYhvCleEQVZ1sTlN33vM_xCelPf5D0vQt6VmS0o8UCV6lJV4KfVfHK8S1QeV1VVRhJz1PbT0yC0DnX0yBHE6WXWSW4d9FUYdEplC3jZZl_xVMkG7w3mKNwK3wXnYduCn8lkh88tvdK5ZUP8VqPdAOFmr_oy8_eRthsmOaoP0C6w9ayApPu4Ty9BZnIRX3T09CgD2XqM4vCfc2T_UygLhLXE6d9YoX-F3DmujFCFqmha1f4Tx_ISTbn1VlhQLz5ZPYer9ZaPIk-zRx3g")
                    }.name = "Code Exchange Auth"
                    stub(condition: isJWKSPath(domain)) { _ in jwksResponse() }
                }

                afterEach {
                    OHHTTPStubs.removeAllStubs()
                    stub(condition: isHost("samples.auth0.com")) { _ in
                        return OHHTTPStubsResponse.init(error: NSError(domain: "com.auth0", code: -99999, userInfo: nil))
                        }.name = "YOU SHALL NOT PASS!"
                }

                it("should return credentials from query string") {
                    let _ = session.resume(URL(string: "https://samples.auth0.com/callback?code=\(code)")!)
                    expect(result).toEventually(haveCredentials())
                }

                it("should return credentials from query when fragment is available") {
                    let _ = session.resume(URL(string: "https://samples.auth0.com/callback?code=\(code)#_=_")!)
                    expect(result).toEventually(haveCredentials())
                }

                it("should return credentials from fragment") {
                    let _ = session.resume(URL(string: "https://samples.auth0.com/callback#code=\(code)")!)
                    expect(result).toEventually(haveCredentials())
                }

                it("should return error from query string") {
                    let _ = session.resume(URL(string: "https://samples.auth0.com/callback?error=error&error_description=description")!)
                    expect(result).toEventually(haveAuthenticationError(code: "error", description: "description"))
                }

                it("should return error from fragment") {
                    let _ = session.resume(URL(string: "https://samples.auth0.com/callback#error=error&error_description=description")!)
                    expect(result).toEventually(haveAuthenticationError(code: "error", description: "description"))
                }

                it("should fail if values from fragment are invalid") {
                    let _ = session.resume(URL(string: "https://samples.auth0.com/callback#code=")!)
                    expect(result).toEventually(beFailure())
                }
            }

            context("with state") {
                let session = SafariSession(controller: controller, redirectURL: RedirectURL, state: "state", handler: handler, finish: {
                    result = $0
                }, logger: nil)

                it("should not handle url when state in url is missing") {
                    let handled = session.resume(URL(string: "https://samples.auth0.com/callback?access_token=ATOKEN&token_type=bearer")!)
                    expect(handled).to(beFalse())
                    expect(result).toEventually(beNil())
                }

                it("should not handle url when state in url does not match one in session") {
                    let handled = session.resume(URL(string: "https://samples.auth0.com/callback?access_token=ATOKEN&token_type=bearer&state=another")!)
                    expect(handled).to(beFalse())
                    expect(result).toEventually(beNil())
                }

            }
        }

    }

}
