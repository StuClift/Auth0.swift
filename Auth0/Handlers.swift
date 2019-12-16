// Handlers.swift
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

func plainJson(from response: Response<AuthenticationError>, callback: Request<[String: Any], AuthenticationError>.Callback) {
    do {
        if let dictionary = try response.result() as? [String: Any] {
            callback(.success(result: dictionary))
        } else {
            callback(.failure(error: AuthenticationError(string: string(response.data))))
        }

    } catch let error {
        callback(.failure(error: error))
    }
}

func codable<T: Codable>(from response: Response<AuthenticationError>, callback: Request<T, AuthenticationError>.Callback) {
    do {
        if let dictionary = try response.result() as? [String: Any] {
            let data = try JSONSerialization.data(withJSONObject: dictionary)
            let decoder = JSONDecoder()
            let decodedObject = try decoder.decode(T.self, from: data)
            
            callback(.success(result: decodedObject))
        } else {
            callback(.failure(error: AuthenticationError(string: string(response.data))))
        }

    } catch let error {
        callback(.failure(error: error))
    }
}

func authenticationObject<T: JSONObjectPayload>(from response: Response<AuthenticationError>, callback: Request<T, AuthenticationError>.Callback) {
    do {
        if let dictionary = try response.result() as? [String: Any], let object = T(json: dictionary) {
            callback(.success(result: object))
        } else {
            callback(.failure(error: AuthenticationError(string: string(response.data))))
        }

    } catch let error {
        callback(.failure(error: error))
    }
}

func databaseUser(from response: Response<AuthenticationError>, callback: Request<DatabaseUser, AuthenticationError>.Callback) {
    do {
        if let dictionary = try response.result() as? [String: Any], let email = dictionary["email"] as? String {
            let username = dictionary["username"] as? String
            let verified = dictionary["email_verified"] as? Bool ?? false
            callback(.success(result: (email: email, username: username, verified: verified)))
        } else {
            callback(.failure(error: AuthenticationError(string: string(response.data))))
        }

    } catch let error {
        callback(.failure(error: error))
    }
}

func noBody(from response: Response<AuthenticationError>, callback: Request<Void, AuthenticationError>.Callback) {
    do {
        _ = try response.result()
        callback(.success(result: ()))
    } catch let error as Auth0Error where error.code == emptyBodyError {
        callback(.success(result: ()))
    } catch let error {
        callback(.failure(error: error))
    }
}

// MARK: - Decorators

func responseHook<T>(_ hook: @escaping (Result<T>, Authentication, @escaping (Result<T>) -> Void) -> Void,
                     after handler: @escaping (Response<AuthenticationError>, @escaping Request<T, AuthenticationError>.Callback) -> Void,
                     authentication: Authentication) -> ((Response<AuthenticationError>, @escaping Request<T, AuthenticationError>.Callback) -> Void) {
    return { response, callback in
        handler(response) { result in
            hook(result, authentication) { result in
                callback(result)
            }
        }
    }
}

func checkIdTokenHook(_ result: Result<Credentials>, authentication: Authentication, callback: @escaping (Result<Credentials>) -> Void) {
    switch result {
    case .success(let credentials):
        let context = IDTokenValidatorContext(domain: authentication.url.host!, clientId: authentication.clientId, jwksRequest: authentication.jwks())
        validate(idToken: credentials.idToken, context: context) { error in
            if let error = error {
                // TODO: Wrap the error
                return callback(Result.failure(error: error))
            }
            callback(result)
    }
    case .failure: callback(result)
    }
}
