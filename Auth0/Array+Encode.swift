// Array+Encode.swift
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

extension Array where Element == UInt8 {
    func a0_derEncode(as type: ASN1Type) -> [UInt8] {
        var derField: [UInt8] = []
        derField.append(type.byte)
        derField.append(contentsOf: lengthField(of: self))
        derField.append(contentsOf: self)
        return derField
    }
}

enum ASN1Type {
    case sequence
    case integer
    case bitString
    case uncompressedIndicator
    
    var byte: UInt8 {
        switch self {
        case .sequence: return 0x30
        case .integer: return 0x02
        case .bitString: return 0x03
        case .uncompressedIndicator: return 0x04
        }
    }
}

private func lengthField(of valueField: [UInt8]) -> [UInt8] {
    var count = valueField.count
    if count < 128 {
        return [ UInt8(count) ]
    }
    // The number of bytes needed to encode count.
    let lengthBytesCount = Int((log2(Double(count)) / 8) + 1)
    // The first byte in the length field encoding the number of remaining bytes.
    let firstLengthFieldByte = UInt8(128 + lengthBytesCount)
    var lengthField: [UInt8] = []
    for _ in 0..<lengthBytesCount {
        // Take the last 8 bits of count.
        let lengthByte = UInt8(count & 0xff)
        // Add them to the length field.
        lengthField.insert(lengthByte, at: 0)
        // Delete the last 8 bits of count.
        count = count >> 8
    }
    // Include the first byte.
    lengthField.insert(firstLengthFieldByte, at: 0)
    return lengthField
}
