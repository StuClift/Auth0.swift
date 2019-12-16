// IDTokenValidator.swift
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
import JWTDecode

class IDTokenValidator {
    private let signatureValidator: JWTSignatureValidator
    private let claimsValidator: JWTClaimsValidator
    private let context: IDTokenValidatorContext
    
    init(signatureValidator: JWTSignatureValidator,
         claimsValidator: JWTClaimsValidator,
         context: IDTokenValidatorContext) {
        self.signatureValidator = signatureValidator
        self.claimsValidator = claimsValidator
        self.context = context
    }

    func validate(_ jwt: JWT, callback: @escaping (LocalizedError?) -> Void) {
        signatureValidator.validate(jwt) { error in
            if let error = error {
                return callback(error)
            }
            callback(self.claimsValidator.validate(jwt))
        }
    }
}

protocol JWTSignatureValidator {
    func validate(_ jwt: JWT, callback: @escaping (LocalizedError?) -> Void)
}

protocol JWTClaimsValidator {
    func validate(_ jwt: JWT) -> LocalizedError?
}

enum JWTAlgorithm: String {
    case rs256 = "RS256"
    
    func verify(_ jwt: JWT, using jwk: JWK) -> Bool {
        switch self {
        case .rs256:
            let separator = "."
            let parts = jwt.string.components(separatedBy: separator).dropLast().joined(separator: separator)
            guard let data = parts.data(using: .utf8),
                let signature = jwt.signature?.a0_decodeBase64URLSafe(),
                let publicKey = jwk.rsaPublicKey,
                let sha256 = A0SHA(algorithm: "sha256"),
                let rsa = A0RSA(key: publicKey) else {
                    return false
            }
            return rsa.verify(sha256.hash(data), signature: signature)
        }
    }
}

class IDTokenClaimsValidator: JWTClaimsValidator {
    private let context: IDTokenValidatorContext
    
    init(context: IDTokenValidatorContext) {
        self.context = context
    }
    
    func validate(_ jwt: JWT) -> LocalizedError? {
        return nil
    }
}

class IDTokenSignatureValidator: JWTSignatureValidator {
    enum ValidationError: LocalizedError, Equatable {
        case invalidAlgorithm(actual: String, expected: String)
        case missingPublicKey(kid: String)
        case invalidSignature
        
        var errorDescription: String? {
            switch self {
            case .invalidAlgorithm(let actual, let expected): return "Signature algorithm of \"\(actual)\" is not supported. Expected the ID token to be signed with \"\(expected)\""
            case .missingPublicKey(let kid): return "Could not find a public key for Key ID (kid) \"\(kid)\""
            case .invalidSignature: return "Invalid ID token signature"
            }
        }
        
        public static func ==(lhs: ValidationError, rhs: ValidationError) -> Bool {
            switch (lhs, rhs) {
            case (.invalidAlgorithm, .invalidAlgorithm): return true
            case (.missingPublicKey, .missingPublicKey): return true
            case (.invalidSignature, .invalidSignature): return true
            default: return false
            }
        }
    }
    
    private let context: IDTokenValidatorContext
    
    init(context: IDTokenValidatorContext) {
        self.context = context
    }
    
    func validate(_ jwt: JWT, callback: @escaping (LocalizedError?) -> Void) {
        let defaultAlgorithm = JWTAlgorithm.rs256.rawValue
        let algValue = jwt.header["alg"] as? String
        guard let alg = algValue, let algorithm = JWTAlgorithm(rawValue: alg) else {
            return callback(ValidationError.invalidAlgorithm(actual: algValue.debugDescription, expected: defaultAlgorithm))
        }
        let kidValue = jwt.header["kid"] as? String
        guard let kid = kidValue else {
            return callback(ValidationError.missingPublicKey(kid: kidValue.debugDescription))
        }
        context
            .jwksRequest
            .start { result in
                switch result {
                case .success(let jwks):
                    guard let jwk = jwks.keys.first(where: {$0.keyId == kid}) else {
                        callback(ValidationError.missingPublicKey(kid: kid))
                        return
                    }
                    algorithm.verify(jwt, using: jwk) ? callback(nil) : callback(ValidationError.invalidSignature)
                case .failure: callback(ValidationError.missingPublicKey(kid: kid))
                }
        }
    }
}

enum IDTokenValidationError: LocalizedError, Equatable {
    case missingToken
    case cannotDecode
    
    var errorDescription: String? {
        switch self {
        case .missingToken: return "ID token is required but missing"
        case .cannotDecode: return "ID token could not be decoded"
        }
    }
    
    public static func ==(lhs: IDTokenValidationError, rhs: IDTokenValidationError) -> Bool {
        switch (lhs, rhs) {
        case (.missingToken, .missingToken): return true
        case (.cannotDecode, .cannotDecode): return true
        default: return false
        }
    }
}

struct IDTokenValidatorContext {
    let domain: String
    let clientId: String
    let jwksRequest: Request<JWKS, AuthenticationError>
}

func validate(idToken: String?,
              context: IDTokenValidatorContext,
              signatureValidator: JWTSignatureValidator? = nil, // for testing
              claimsValidator: JWTClaimsValidator? = nil,
              callback: @escaping (LocalizedError?) -> Void) {
    guard let idToken = idToken else {
        return callback(IDTokenValidationError.missingToken)
    }
    guard let jwt = try? decode(jwt: idToken) else {
        return callback(IDTokenValidationError.cannotDecode)
    }
    
    let validator = IDTokenValidator(signatureValidator: signatureValidator ?? IDTokenSignatureValidator(context: context),
                                     claimsValidator: claimsValidator ?? IDTokenClaimsValidator(context: context),
                                     context: context)
    validator.validate(jwt, callback: callback)
}
