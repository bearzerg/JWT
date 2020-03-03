import Foundation

public class JWT {
    
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
        do {
            let headerString = try JSONSerialization.data(withJSONObject: header, options: []).base64URLEncodedString()
            let payloadString = try JSONSerialization.data(withJSONObject: payload, options: []).base64URLEncodedString()
            
            let rawSign = "\(headerString).\(payloadString)"
            
            if let sign = Cryptor.hmac(string: rawSign, algorithm: alg.forCryptor, key: secret) {
                return "\(rawSign).\(sign)"
            } else {
                print("JWT: Can't compute sign.")
                return nil
            }
        } catch let err {
            print(err.localizedDescription)
            return nil
        }
    }
}

//MARK: - Token decoding
extension JWT {
    public convenience init?(token: String) {
        let elements = token.split(separator: ".").map({String($0)})
        guard
            elements.count == 3 else {
                print("JWT: Wrong format!")
                return nil
        }
        
        guard let headerData = Data(base64URLEncoded: elements[0]),
            let payloadData = Data(base64URLEncoded: elements[1]) else {
                print("JWT: Wrong format!")
                print("Failed to parse header/payload.")
                return nil
        }
        
        do {
            guard let header = try JSONSerialization.jsonObject(with: headerData, options: []) as? [String: String],
                let payload = try JSONSerialization.jsonObject(with: payloadData, options: []) as? [String: String]
                else {
                    print("JWT: Failed to parse header/payload.")
                    return nil
            }
            
            guard let algString = header["alg"] else {
                print("JWT: Can't define algorithm.")
                return nil
            }
            guard let alg = Algorithm(rawValue: algString) else {
                print("JWT: Alghoritm doesn't support.")
                return nil
            }
            
            self.init(alg: alg, secret: "")
            self.header = header
            self.payload = payload
            
        } catch let err {
            print(err.localizedDescription)
            return nil
        }
    }
}
