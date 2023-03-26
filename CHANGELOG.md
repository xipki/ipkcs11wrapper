# Change Log

See also <https://github.com/xipki/ipkcs11wrapper/releases>

## 1.0.5
- Release date: 2023/xx/xx
- N/A

## 1.0.4
- Release date: 2023/03/26
- Replace Date and Calendar with java.time.*.
- Log created object, if TRACE is enabled.

## 1.0.3
- Release date: 2023/03/18
- Session.java: log operations.
- Corrected vendor behaviour of the TASS HSM
- Add KCS11Token to wrap Session. Using this class the application does 
  not need to manage (login, logout, open session, etc.) the sessions.

## 1.0.2
- Release date: 2023/03/05
- Add mechanism to log warn/error messages.
- Session.java: add method getDefaultAttrValues() to get all default attribute values of an object.
- session.java: add method findObjectsSingle, signSingle, verifySingle, encryptSingle, decryptSingle, etc.

## 1.0.1
- Release date: 2023/02/27
- First release version of ipkcs11wrapper
