import Foundation

struct KeychainPasswordAccess {
    
    enum KeychainError: Error {
        case noPassword
        case unexpectedPasswordData
        case unhandledError(status: OSStatus)
    }
    
    private var account: String
    private var service: String
    private var accessGroup: String?
    
    init(service: String, account: String, accessGroup: String? = nil) {
        self.service = service
        self.account = account
        self.accessGroup = accessGroup
    }
    
    func savePassword(_ value: String) throws {
        do {
            try _ = readPassword()
            try self.updatePassword(value)
            
        } catch KeychainError.noPassword {
            let query = self.savePasswordQuery(withService: self.service,
                                               password: value,
                                               account: self.account,
                                               accessGroup: self.accessGroup)
            
            let status = SecItemAdd(query as CFDictionary, nil)
            guard status == errSecSuccess else {
                throw KeychainError.unhandledError(status: status)
            }
        }
    }
    
    func updatePassword(_ password: String) throws {
        let encodedPassword = encodePassword(password)
        var attributesToUpdate = [String : Any]()
        attributesToUpdate[kSecValueData as String] = encodedPassword as Any?
        
        let query = self.query(withService: self.service,
                               account: self.account,
                               accessGroup: self.accessGroup)
        
        let status = SecItemUpdate(query as CFDictionary, attributesToUpdate as CFDictionary)
        guard status == noErr else {
            throw KeychainError.unhandledError(status: status)
        }
    }
    
    func readPassword() throws -> String {
        let query = self.readPasswordQuery(withService: self.service,
                                           account: self.account,
                                           accessGroup: self.accessGroup)
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        
        guard status != errSecItemNotFound else {
            throw KeychainError.noPassword
        }
        guard status == errSecSuccess else {
            throw KeychainError.unhandledError(status: status)
        }
        guard let existingItem = item as? [String : Any],
            let passwordData = existingItem[kSecValueData as String] as? Data,
            let password = String(data: passwordData, encoding: String.Encoding.utf8)
            else {
                throw KeychainError.unexpectedPasswordData
        }
        return password
    }
    
    func deletePassword() throws {
        let query = self.query(withService: self.service,
                               account: self.account,
                               accessGroup: self.accessGroup)
        let status = SecItemDelete(query as CFDictionary)
        guard status == noErr || status == errSecItemNotFound else {
            throw KeychainError.unhandledError(status: status)
        }
    }
    
    private func encodePassword(_ password: String) -> Data {
        return password.data(using: String.Encoding.utf8)!
    }
    
    private func savePasswordQuery(withService service: String,
                                   password: String,
                                   account: String?,
                                   accessGroup: String?) -> [String : Any] {
        
        var query = self.query(withService: self.service, account: self.account, accessGroup: self.accessGroup)
        let encodedPassword = encodePassword(password)
        query[kSecValueData as String] = encodedPassword as Any?
        return query
    }
    
    private func readPasswordQuery(withService service: String,
                                   account: String?,
                                   accessGroup: String?) -> [String : Any] {
        
        var query = self.query(withService: self.service, account: self.account, accessGroup: self.accessGroup)
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        query[kSecReturnAttributes as String] = kCFBooleanTrue
        query[kSecReturnData as String] = kCFBooleanTrue
        return query
    }
    
    private func query(withService service: String,
                       account: String?,
                       accessGroup: String?) -> [String : Any] {
        
        var query = [String : Any]()
        query[kSecClass as String] = kSecClassGenericPassword
        query[kSecAttrService as String] = service as Any?
        
        if let account = account {
            query[kSecAttrAccount as String] = account as Any?
        }
        
        if let accessGroup = accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup as Any?
        }
        
        return query
    }
}
