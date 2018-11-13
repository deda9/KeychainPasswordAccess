# KeychainPasswordAccess

It's just a wrapper to access the keychain for CRUD operations, so its more safe to save the user password in Keychain rather than UserDefaults.

in default way to save the user name, we write this 
```Swift
  func testSavedPassword() {
        let service = "ServiceName"
        let account = "UserAccount"
        let password = "UserPassword"
        
        do {
            let keyChainAccess = KeychainPasswordAccess(service: service, account: account)
            try keyChainAccess.deletePassword()
            try keyChainAccess.savePassword(password)
            let savedPasswrod = try keyChainAccess.readPassword()
        } catch {
            print("Error while saving the password", error)
        }
}````


