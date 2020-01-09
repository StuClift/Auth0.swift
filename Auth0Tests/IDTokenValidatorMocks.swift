// IDTokenValidatorMocks.swift
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

@testable import Auth0

class MockIDTokenSignatureValidator: JWTSignatureValidator {
    func validate(_ jwt: JWT, callback: @escaping (LocalizedError?) -> Void) {
        callback(nil)
    }
}

class MockIDTokenClaimsValidator: JWTClaimValidator {
    func validate(_ jwt: JWT) -> LocalizedError? {
        return nil
    }
}

class MockSuccessfulIDTokenClaimValidator: JWTClaimValidator {
    func validate(_ jwt: JWT) -> LocalizedError? {
        return nil
    }
}

class MockUnsuccessfulIDTokenClaimValidator: JWTClaimValidator {
    enum ValidationError: LocalizedError {
        case errorCase1
        case errorCase2
        
        var errorDescription: String? {
            return "Error message"
        }
    }
    
    let errorCase: ValidationError
    
    init(errorCase: ValidationError = .errorCase1) {
        self.errorCase = errorCase
    }
    
    func validate(_ jwt: JWT) -> LocalizedError? {
        return errorCase
    }
}

class SpyUnsuccessfulIDTokenClaimValidator: JWTClaimValidator {
    enum ValidationError: LocalizedError {
        case errorCase
        
        var errorDescription: String? {
            return "Error message"
        }
    }
    
    var didExecuteValidation: Bool = false
    
    func validate(_ jwt: JWT) -> LocalizedError? {
        didExecuteValidation = true
        
        return ValidationError.errorCase
    }
}
