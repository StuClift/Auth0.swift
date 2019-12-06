// OAuth2Grant.swift
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

import Foundation
import JWTDecode

protocol OAuth2Grant {
    var defaults: [String: String] { get }
    func credentials(from values: [String: String], callback: @escaping (Result<Credentials>) -> Void)
    func values(fromComponents components: URLComponents) -> [String: String]
}

struct ImplicitGrant: OAuth2Grant {

    let authentication: Authentication
    let defaults: [String: String]
    let responseType: [ResponseType]

    init(authentication: Authentication, responseType: [ResponseType] = [.token], nonce: String? = nil) {
        self.authentication = authentication
        self.responseType = responseType
        if let nonce = nonce {
            self.defaults = ["nonce": nonce]
        } else {
            self.defaults = [:]
        }
    }

    func credentials(from values: [String: String], callback: @escaping (Result<Credentials>) -> Void) {
        let responseType = self.responseType
        validate(responseType: self.responseType,
                 token: values["id_token"],
                 nonce: self.defaults["nonce"],
                 authentication: self.authentication) { error in
            if let error = error {
                // TODO: Wrap the error
                return callback(.failure(error: error))
            }
            guard !responseType.contains(.token) || values["access_token"] != nil else {
                return callback(.failure(error: WebAuthError.missingAccessToken))
            }

            callback(.success(result: Credentials(json: values as [String: Any])))
        }
    }

    func values(fromComponents components: URLComponents) -> [String: String] {
        return components.a0_fragmentValues
    }

}

struct PKCE: OAuth2Grant {

    let authentication: Authentication
    let redirectURL: URL
    let defaults: [String: String]
    let verifier: String
    let responseType: [ResponseType]

    init(authentication: Authentication, redirectURL: URL, generator: A0SHA256ChallengeGenerator = A0SHA256ChallengeGenerator(), reponseType: [ResponseType] = [.code], nonce: String? = nil) {
        self.init(authentication: authentication, redirectURL: redirectURL, verifier: generator.verifier, challenge: generator.challenge, method: generator.method, responseType: reponseType, nonce: nonce)
    }

    init(authentication: Authentication, redirectURL: URL, verifier: String, challenge: String, method: String, responseType: [ResponseType], nonce: String? = nil) {
        self.authentication = authentication
        self.redirectURL = redirectURL
        self.verifier = verifier
        self.responseType = responseType

        var newDefaults: [String: String] = [
            "code_challenge": challenge,
            "code_challenge_method": method
        ]

        if let nonce = nonce {
            newDefaults["nonce"] = nonce
        }

        self.defaults = newDefaults
    }

    func credentials(from values: [String: String], callback: @escaping (Result<Credentials>) -> Void) {
        guard let code = values["code"] else {
            let string = "No code found in parameters \(values)"
            return callback(.failure(error: AuthenticationError(string: string)))
        }
        let idToken = values["id_token"]
        let isHybridFlow = self.responseType.contains(.idToken)
        let verifier = self.verifier
        let redirectUrlString = self.redirectURL.absoluteString
        let clientId = self.authentication.clientId
        validate(responseType: self.responseType, token: idToken, nonce: self.defaults["nonce"], authentication: self.authentication) { [authentication = self.authentication] error in
            if let error = error {
                // TODO: Wrap the error
                return callback(.failure(error: error))
            }
            authentication
                .tokenExchange(withCode: code, codeVerifier: verifier, redirectURI: redirectUrlString)
                .start { result in
                    switch result {
                    case .failure(let error as AuthenticationError):
                        if error.description == "Unauthorized" {
                            // Special case for PKCE when the correct method for token endpoint authentication is not set (it should be None)
                            let webAuthError = WebAuthError.pkceNotAllowed("Unable to complete authentication with PKCE. PKCE support can be enabled by setting Application Type to 'Native' and Token Endpoint Authentication Method to 'None' for this app at 'https://manage.auth0.com/#/applications/\(clientId)/settings'.")
                            return callback(Result.failure(error: webAuthError))
                        }
                    case .failure: return callback(result)
                    case .success(let credentials):
                        switch getAlgorithm(jwt: idToken) {
                        case .rs256:
                            if isHybridFlow {
                                let newCredentials = Credentials(accessToken: credentials.accessToken,
                                                                 tokenType: credentials.tokenType,
                                                                 idToken: idToken,
                                                                 refreshToken: credentials.refreshToken,
                                                                 expiresIn: credentials.expiresIn,
                                                                 scope: credentials.scope)
                                return callback(Result.success(result: newCredentials))
                            }
                        case .none: break
                        }
                        return validate(idToken: credentials.idToken, authentication: authentication) { error in
                            if let error = error {
                                // TODO: Wrap error
                                print("VALIDATION FAILED")
                                return callback(Result.failure(error: error))
                            }
                            print("VALIDATION SUCCESSFUL")
                            callback(result)
                        }
                    }
                callback(result)
            }
        }
    }

    func values(fromComponents components: URLComponents) -> [String: String] {
        var items = components.a0_fragmentValues
        components.a0_queryValues.forEach { items[$0] = $1 }
        return items
    }
}

private func validate(responseType: [ResponseType], token: String?, nonce: String?, authentication: Authentication, callback: @escaping (LocalizedError?) -> Void) {
    guard responseType.contains(.idToken) else { // Code flow case, below is Hybrid flow
        return callback(nil)
    }
    guard let expectedNonce = nonce, let token = token else {
        return callback(WebAuthError.invalidIdTokenNonce)
    }
    let credentials = Credentials(accessToken: nil, tokenType: nil, idToken: token, refreshToken: nil, expiresIn: nil, scope: nil)
    validate(idToken: credentials.idToken, authentication: authentication) { error in
        if let error = error {
            // TODO: Wrap error
            print("VALIDATION FAILED")
            return callback(error)
        }
        print("VALIDATION SUCCESSFUL")
        // Will be done with the claims validation
        if getNonce(jwt: token) != expectedNonce {
            callback(WebAuthError.invalidIdTokenNonce)
        } else {
            callback(nil)
        }
    }
}

private func getAlgorithm(jwt: String?) -> JWTAlgorithm? {
    guard let jwt = jwt, let decodedJwt = try? decode(jwt: jwt), let alg = decodedJwt.header["alg"] as? String else { return nil }
    return JWTAlgorithm(rawValue: alg)
}

// TODO: Remove after implementing claims validation
private func getNonce(jwt: String?) -> String? {
    guard let jwt = jwt, let decodedJwt = try? decode(jwt: jwt) else { return nil }
    return decodedJwt.claim(name: "nonce").string
}
