// ClaimsValidators.swift
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
import JWTDecode

protocol IDTokenClaimsContext {
    var domain: String { get }
    var clientId: String { get }
    var leeway: Int { get }
    var nonce: String? { get }
    var maxAge: Int? { get }
}

final class IDTokenClaimsValidator: JWTClaimValidator {
    private var validators: [JWTClaimValidator]
    
    init(validators: [JWTClaimValidator]) {
        self.validators = validators
    }
    
    func validate(_ jwt: JWT) -> LocalizedError? {
        return validators.first { $0.validate(jwt) != nil }?.validate(jwt)
    }
}

final class IDTokenIssValidator: JWTClaimValidator {
    enum ValidationError: LocalizedError, Equatable {
        case missingIss
        case mismatchedIss(actual: String, expected: String)
        
        var errorDescription: String? {
            switch self {
            case .missingIss: return "Issuer (iss) claim must be a string present in the ID token"
            case .mismatchedIss(let actual, let expected):
                return "Issuer (iss) claim mismatch in the ID token, expected (\(expected)), found (\(actual))"
            }
        }
        
        public static func == (lhs: ValidationError, rhs: ValidationError) -> Bool {
            switch (lhs, rhs) {
            case (.missingIss, .missingIss): return true
            case (.mismatchedIss, .mismatchedIss): return true
            default: return false
            }
        }
    }
    
    private let domain: String
    
    init(domain: String) {
        self.domain = domain
    }
    
    func validate(_ jwt: JWT) -> LocalizedError? {
        guard let iss = jwt.issuer else { return ValidationError.missingIss }
        guard URL(string: iss)?.host == domain else {
            return ValidationError.mismatchedIss(actual: iss, expected: domain)
        }
        return nil
    }
}

final class IDTokenSubValidator: JWTClaimValidator {
    enum ValidationError: LocalizedError, Equatable {
        case missingSub
        
        var errorDescription: String? {
            switch self {
            case .missingSub: return "Subject (sub) claim must be a string present in the ID token"
            }
        }
        
        public static func == (lhs: ValidationError, rhs: ValidationError) -> Bool {
            switch (lhs, rhs) {
            case (.missingSub, .missingSub): return true
            }
        }
    }
    
    func validate(_ jwt: JWT) -> LocalizedError? {
        guard let sub = jwt.subject, !sub.isEmpty else { return ValidationError.missingSub }
        return nil
    }
}

final class IDTokenAudValidator: JWTClaimValidator {
    enum ValidationError: LocalizedError, Equatable {
        case missingAud
        case mismatchedAud(actual: String, expected: String)
        case mismatchedAudArray(actual: String, expected: String)
        
        var errorDescription: String? {
            switch self {
            case .missingAud:
                return "Audience (aud) claim must be a string or array of strings present in the ID token"
            case .mismatchedAud(let actual, let expected):
                return "Audience (aud) claim mismatch in the ID token; expected (\(expected)) but found (\(actual))"
            case .mismatchedAudArray(let actual, let expected):
                return "Audience (aud) claim mismatch in the ID token; expected (\(expected)) but was not one of (\(actual))"
            }
        }
        
        public static func == (lhs: ValidationError, rhs: ValidationError) -> Bool {
            switch (lhs, rhs) {
            case (.missingAud, .missingAud): return true
            case (.mismatchedAud, .mismatchedAud): return true
            case (.mismatchedAudArray, .mismatchedAudArray): return true
            default: return false
            }
        }
    }
    
    let clientId: String
    
    init(clientId: String) {
        self.clientId = clientId
    }
    
    func validate(_ jwt: JWT) -> LocalizedError? {
        guard let aud = jwt.audience, !aud.isEmpty else { return ValidationError.missingAud }
        guard aud.contains(clientId) else {
            return aud.count == 1 ?
                ValidationError.mismatchedAud(actual: aud.first!, expected: clientId) :
                ValidationError.mismatchedAudArray(actual: aud.joined(separator: ", "), expected: clientId)
        }
        return nil
    }
}

final class IDTokenExpValidator: JWTClaimValidator {
    enum ValidationError: LocalizedError, Equatable {
        case missingExp
        case pastExp(currentTime: Double, expirationTime: Double)
        
        var errorDescription: String? {
            switch self {
            case .missingExp: return "Expiration time (exp) claim must be a number present in the ID token"
            case .pastExp(let currentTime, let expirationTime):
                return "Expiration time (exp) claim error in the ID token; current time (\(currentTime)) is after expiration time (\(expirationTime))"
            }
        }
        
        public static func == (lhs: ValidationError, rhs: ValidationError) -> Bool {
            switch (lhs, rhs) {
            case (.missingExp, .missingExp): return true
            case (.pastExp, .pastExp): return true
            default: return false
            }
        }
    }
    
    private let leeway: Int
    
    init(leeway: Int) {
        self.leeway = leeway
    }
    
    func validate(_ jwt: JWT) -> LocalizedError? {
        guard let exp = jwt.expiresAt else { return ValidationError.missingExp }
        let currentTimeEpoch = Date().timeIntervalSince1970
        let expEpoch = exp.timeIntervalSince1970 + Double(leeway)
        guard expEpoch < currentTimeEpoch else {
            return ValidationError.pastExp(currentTime: currentTimeEpoch, expirationTime: expEpoch)

        }
        return nil
    }
}

final class IDTokenIatValidator: JWTClaimValidator {
    enum ValidationError: LocalizedError, Equatable {
        case missingIat
        
        var errorDescription: String? {
            switch self {
            case .missingIat: return "Issued At (iat) claim must be a number present in the ID token"
            }
        }
        
        public static func == (lhs: ValidationError, rhs: ValidationError) -> Bool {
            switch (lhs, rhs) {
            case (.missingIat, .missingIat): return true
            }
        }
    }
    
    func validate(_ jwt: JWT) -> LocalizedError? {
        guard jwt.issuedAt != nil else { return ValidationError.missingIat }
        return nil
    }
}

final class IDTokenNonceValidator: JWTClaimValidator {
    enum ValidationError: LocalizedError, Equatable {
        case missingNonce
        case mismatchedNonce(actual: String, expected: String)
        
        var errorDescription: String? {
            switch self {
            case .missingNonce: return "Nonce (nonce) claim must be a string present in the ID token"
            case .mismatchedNonce(let actual, let expected):
                return "Nonce (nonce) claim value mismatch in the ID token; expected (\(expected)), found (\(actual))"
            }
        }
        
        public static func == (lhs: ValidationError, rhs: ValidationError) -> Bool {
            switch (lhs, rhs) {
            case (.missingNonce, .missingNonce): return true
            case (.mismatchedNonce, .mismatchedNonce): return true
            default: return false
            }
        }
    }
    
    private let nonce: String
    
    init(nonce: String) {
        self.nonce = nonce
    }
    
    func validate(_ jwt: JWT) -> LocalizedError? {
        guard let nonceClaim = jwt.claim(name: "nonce").string else { return ValidationError.missingNonce }
        guard nonceClaim == nonce else {
            return ValidationError.mismatchedNonce(actual: nonceClaim, expected: nonce)

        }
        return nil
    }
}

final class IDTokenAzpValidator: JWTClaimValidator {
    enum ValidationError: LocalizedError, Equatable {
        case missingAzp
        case mismatchedAzp(actual: String, expected: String)
        
        var errorDescription: String? {
            switch self {
            case .missingAzp:
                return "Authorized Party (azp) claim must be a string present in the ID token when Audience (aud) claim has multiple values"
            case .mismatchedAzp(let actual, let expected):
                return "Authorized Party (azp) claim mismatch in the ID token; expected (\(expected)), found (\(actual))"
            }
        }
        
        public static func == (lhs: ValidationError, rhs: ValidationError) -> Bool {
            switch (lhs, rhs) {
            case (.missingAzp, .missingAzp): return true
            case (.mismatchedAzp, .mismatchedAzp): return true
            default: return false
            }
        }
    }
    
    let clientId: String
    
    init(clientId: String) {
        self.clientId = clientId
    }
    
    func validate(_ jwt: JWT) -> LocalizedError? {
        guard let azp = jwt.claim(name: "azp").string else { return ValidationError.missingAzp }
        guard azp == clientId else {
            return ValidationError.mismatchedAzp(actual: azp, expected: clientId)
        }
        return nil
    }
}

final class IDTokenAuthTimeValidator: JWTClaimValidator {
    enum ValidationError: LocalizedError, Equatable {
        case missingAuthTime
        case pastLastAuth(currentTime: Double, lastAuthTime: Double)
        
        var errorDescription: String? {
            switch self {
            case .missingAuthTime:
                return "Authentication Time (auth_time) claim must be a number present in the ID token when Max Age (max_age) is specified"
            case .pastLastAuth(let currentTime, let lastAuthTime):
                return "Authentication Time (auth_time) claim in the ID token indicates that too much time has passed since the last end-user authentication. Current time (\(currentTime)) is after last auth time (\(lastAuthTime))"
            }
        }
        
        public static func == (lhs: ValidationError, rhs: ValidationError) -> Bool {
            switch (lhs, rhs) {
            case (.missingAuthTime, .missingAuthTime): return true
            case (.pastLastAuth, .pastLastAuth): return true
            default: return false
            }
        }
    }
    
    private let leeway: Int
    private let maxAge: Int
    
    init(leeway: Int, maxAge: Int) {
        self.leeway = leeway
        self.maxAge = maxAge
    }
    
    func validate(_ jwt: JWT) -> LocalizedError? {
        guard let authTime = jwt.claim(name: "auth_time").date else { return ValidationError.missingAuthTime }
        let currentTime = Date().timeIntervalSince1970
        let authTimeEpoch = authTime.timeIntervalSince1970 + Double(maxAge) + Double(leeway)
        guard currentTime < authTimeEpoch else { return ValidationError.pastLastAuth(currentTime: currentTime, lastAuthTime: authTimeEpoch) }
        return nil
    }
}
