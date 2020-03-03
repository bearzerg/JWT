import Foundation

public class JWT {
    
    public init?(token: String) {
        let elements = token.split(separator: ".")
        if elements.count != 3 { return nil }
        let headerString = String(elements[0])
        let payloadString = String(elements[1])
        let secretString = String(elements[2])
        
        guard let headerData = Data(base64URLEncoded: headerString),
            let header = try? JSONSerialization.jsonObject(with: headerData, options: []) as? [String: String],
            let payloadData = Data(base64URLEncoded: payloadString),
            let payload = try? JSONSerialization.jsonObject(with: payloadData, options: []) as? [String: String]
            else { return nil }
        
        guard let algString = header["alg"] else { return nil }
        guard let alg = Algorithm(rawValue: algString) else {
            print("Alghoritm doesn't support.")
            return nil
        }
        self.alg = alg
        self.header = header
        self.payload = payload
        self.secret = ""
    }
    
    public init(alg: JWT.Algorithm = .HS256, secret: String = "") {
        self.alg = alg
        self.header["alg"] = alg.rawValue
        self.header["typ"] = "JWT"
        self.secret = secret
    }
    
    public enum Algorithm: String {
        case HS256
        case HS384
        case HS512
        
        var forCryptor: Cryptor.Algorithm {
            switch self {
            case .HS256: return .SHA256
            case .HS384: return .SHA384
            case .HS512: return .SHA512
            }
        }
    }
    var alg: Algorithm
    
    public var header: [String: String] = [:]
    public var payload: [String: String] = [:]
    public var secret: String
    
    public var token: String? {
        guard let headerString = try? JSONSerialization.data(withJSONObject: header, options: []).base64URLEncodedString() else { return nil }
        guard let payloadString = try? JSONSerialization.data(withJSONObject: payload, options: []).base64URLEncodedString() else { return nil }
        
        let rawSign = "\(headerString).\(payloadString)"
        
        if let sign = Cryptor.hmac(string: rawSign, algorithm: alg.forCryptor, key: secret) {
            return "\(rawSign).\(sign)"
        }
        return nil
    }
}
