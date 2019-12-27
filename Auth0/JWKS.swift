// JWKS.swift
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
import Security

public struct JWKS: Codable {
    let keys: [JWK]
}

extension JWKS {
    func key(id kid: String) -> JWK? {
        return keys.first { $0.keyId == kid }
    }
}

public struct JWK: Codable {
    let keyType: String
    let keyId: String?
    let usage: String?
    let algorithm: String?
    let certUrl: String?
    let certThumbprint: String?
    let certChain: [String]?
    let rsaModulus: String?
    let rsaExponent: String?

    enum CodingKeys: String, CodingKey {
        case keyType = "kty"
        case keyId = "kid"
        case usage = "use"
        case algorithm = "alg"
        case certUrl = "x5u"
        case certThumbprint = "x5t"
        case certChain = "x5c"
        case rsaModulus = "n"
        case rsaExponent = "e"
    }
}

extension JWK {
    var rsaPublicKey: SecKey? {
        guard let modulus = rsaModulus?.a0_decodeBase64URLSafe(), let exponent = rsaExponent?.a0_decodeBase64URLSafe() else {
            return nil
        }
        var modulusBytes = [UInt8](modulus)
        if let firstByte = modulusBytes.first, firstByte >= 0x80 {
            modulusBytes.insert(0x00, at: 0)
        }
        let exponentBytes = [UInt8](exponent)
        let modulusEncoded = modulusBytes.a0_derEncode(as: 2)
        let exponentEncoded = exponentBytes.a0_derEncode(as: 2)
        let sequenceEncoded = (modulusEncoded + exponentEncoded).a0_derEncode(as: 48)
        let data = Data(sequenceEncoded)
        let sizeInBits = data.count * MemoryLayout<UInt8>.size
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits: NSNumber(value: sizeInBits)
        ]
        var error: Unmanaged<CFError>?
        return SecKeyCreateWithData(data as CFData, attributes as CFDictionary, &error)
    }
}
