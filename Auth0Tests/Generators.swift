// Generators.swift
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

// MARK: - Keys

enum TestKeys {
    static let rsaPrivate: SecKey = {
        let query: [String: Any] = [
            String(kSecAttrKeyType): kSecAttrKeyTypeRSA,
            String(kSecAttrKeySizeInBits): 2048,
        ]
        
        return SecKeyCreateRandomKey(query as CFDictionary, nil)!
    }()
    
    static let rsaPublic: SecKey = {
        return SecKeyCopyPublicKey(rsaPrivate)!
    }()
}

// MARK: - JWT

private func encodeJWTPart(from dict: [String: Any]) -> String {
    let json = try! JSONSerialization.data(withJSONObject: dict, options: JSONSerialization.WritingOptions())
    
    return json.a0_encodeBase64URLSafe()!
}

private func generateJWTHeader(alg: String, kid: String) -> String {
    let headerDict: [String: Any] = ["alg": alg, "kid": kid]
    
    return encodeJWTPart(from: headerDict)
}

private func generateJWTBody(alg: String,
                             kid: String,
                             iss: String,
                             sub: String,
                             aud: [String],
                             exp: Date,
                             iat: Date,
                             azp: String?,
                             maxAge: Int?,
                             authTime: Date?,
                             nonce: String) -> String {
    var bodyDict: [String: Any] = [
        "iss": iss,
        "sub": sub,
        "aud": aud.count == 1 ? aud[0] : aud,
        "exp": exp.timeIntervalSince1970,
        "iat": iat.timeIntervalSince1970,
        "nonce": nonce
    ]
    
    if let azp = azp {
        bodyDict["azp"] = azp
    }
    
    if let maxAge = maxAge {
        bodyDict["max_age"] = maxAge
    }
    
    if let authTime = authTime {
        bodyDict["auth_time"] = authTime.timeIntervalSince1970
    }
    
    return encodeJWTPart(from: bodyDict)
}

func generateJWT(alg: String = JWTAlgorithm.rs256.rawValue,
                 kid: String = "key123",
                 iss: String = "https://tokens-test.auth0.com/",
                 sub: String = "auth0|123456789",
                 aud: [String] = ["tokens-test-123"],
                 exp: Date = Date().addingTimeInterval(100000),
                 iat: Date = Date().addingTimeInterval(-1000),
                 azp: String? = nil,
                 maxAge: Int? = nil,
                 authTime: Date? = nil,
                 nonce: String = "a1b2c3d4e5") -> JWT {
    let header = generateJWTHeader(alg: alg, kid: kid)
    let body = generateJWTBody(alg: alg,
                               kid: kid,
                               iss: iss,
                               sub: sub,
                               aud: aud,
                               exp: exp,
                               iat: iat,
                               azp: azp,
                               maxAge: maxAge,
                               authTime: authTime,
                               nonce: nonce)
    
    let signableParts = "\(header).\(body)"
    var signature = "SIGNATURE"
    
    if let algorithm = JWTAlgorithm(rawValue: alg) {
        signature = algorithm.sign(value: signableParts.data(using: .utf8)!).a0_encodeBase64URLSafe()!
    }
    
    return try! decode(jwt: "\(signableParts).\(signature)")
}

// MARK: - JWK

private func calculateLength(from bytes: UnsafePointer<UInt8>) -> (UnsafePointer<UInt8>, Int) {
    guard bytes.pointee > 0x7f else {
        return (bytes + 1, Int(bytes.pointee))
    }

    let count = Int(bytes.pointee & 0x7f)
    let length = (1...count).reduce(0) { ($0 << 8) + Int(bytes[$1]) }
    let pointer = bytes + (1 + count)
    
    return (pointer, length)
}

private func extractData(from bytes: UnsafePointer<UInt8>) -> (UnsafePointer<UInt8>, Data)? {
    guard bytes.pointee == 0x02 else { return nil }
    
    let (valueBytes, valueLength) = calculateLength(from: bytes + 1)
    let data = Data(bytes: valueBytes, count: valueLength)
    let pointer = valueBytes + valueLength
    
    return (pointer, data)
}

func generateRSAJWK(from publicKey: SecKey = TestKeys.rsaPublic) -> JWK {
    let asn = { (bytes: UnsafePointer<UInt8>) -> JWK? in
        guard bytes.pointee == 0x30 else { return nil }
        
        let (modulusBytes, totalLength) = calculateLength(from: bytes + 1)
        
        guard totalLength > 0, let (exponentBytes, modulus) = extractData(from: modulusBytes) else { return nil }
        guard let (end, exponent) = extractData(from: exponentBytes) else { return nil }
        guard abs(end.distance(to: modulusBytes)) == totalLength else { return nil }
        
        let encodedModulus = modulus.a0_encodeBase64URLSafe()
        let encodedExponent = exponent.a0_encodeBase64URLSafe()
        
        return JWK(keyType: "RSA",
                   keyId: "key123",
                   usage: "sig",
                   algorithm: JWTAlgorithm.rs256.rawValue,
                   certUrl: nil,
                   certThumbprint: nil,
                   certChain: nil,
                   rsaModulus: encodedModulus,
                   rsaExponent: encodedExponent)
    }
    
    return publicKey.export().withUnsafeBytes { unsafeRawBufferPointer in
        return asn(unsafeRawBufferPointer.bindMemory(to: UInt8.self).baseAddress!)!
    }
}
