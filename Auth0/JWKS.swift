//
//  JWKS.swift
//  Auth0
//
//  Created by Rita Zerrizuela on 05/12/2019.
//  Copyright © 2019 Auth0. All rights reserved.
//

import Foundation
import Security

public struct JWKS: Codable {
    let keys: [JWK]
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
        let modulusEncoded = modulusBytes.a0_derEncode(as: .integer)
        let exponentEncoded = exponentBytes.a0_derEncode(as: .integer)
        let sequenceEncoded = (modulusEncoded + exponentEncoded).a0_derEncode(as: .sequence)
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
