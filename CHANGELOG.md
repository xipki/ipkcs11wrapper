# Change Log

See also <https://github.com/xipki/ipkcs11wrapper/releases>

## 1.0.8
- Release date: yyyy/mm/dd
- Feature: log the library version.
- Feature: simplify the concurrent bag.
- Feature: log th mechanism code and parameter more accurately

## 1.0.7
- Release date: 2023/10/15
- Feature: remove the limitation of CKD in ECDH1_DERIVE and ECDH2_DERIVE
- Feature: cache the mechanism codes and infos of token.
 
## 1.0.6
- Release date: 2023/08/31
- Bugfix: fixed encoding of CKA_EC_POINT of edwards and montgomery curves.
- Feature: add vendor conf to ignore ulDeviceError
- Feature: extend vendor conf of ncipher HSMs
- Feature: add vendor conf to force use curve name instead curve OID.
- Feature: add conf of timeout to borrow idle sessions.
- Feature: allow the specification of PIN even if ProtectedAuthenticationPath is true.
- Feature: more stable session login

## 1.0.5
- Release date: 2023/04/29
- Bugfix: Fixed OutOfMemory Exception in findObjects(int num) with large num.
- Bugfix: Fixed NullPointerException while reading attributes of a key if CKA_CLASS or CKA_KEY_TYPE is not set.
- Bugfix: Fixed bug "Vendor configuration file cannot be specified via explicit property". 
- Feature: Allow the configuration of vendor values CKM_*, CKR_*, CKK_* and CKD_*.
- Feature: Add the vendor constants of Utimaco HSM and Safenet HSM.

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
