## TODO
- Fix bug "thread crashes when reading an existing CKA_WRAP_TEMPLATE and CKA_UNWRAP_TEMPLATE"
  - The C code of JNI needs to be adapted
  - The result can be verified by the class demo.pkcs.pkcs11.wrapper.basics.TestReadUnwrapTemplate.

- Add new JNI functions, as in the cryptoki implementation of JDK.
  - In C: For Encryption
    - https://github.com/openjdk/jdk/blob/master/src/jdk.crypto.cryptoki/share/native/libj2pkcs11/p11_crypt.c#L129
    - https://github.com/openjdk/jdk/blob/master/src/jdk.crypto.cryptoki/share/native/libj2pkcs11/p11_crypt.c#L195
    - https://github.com/openjdk/jdk/blob/master/src/jdk.crypto.cryptoki/share/native/libj2pkcs11/p11_crypt.c#L259
  - In C: For Decryption
    - https://github.com/openjdk/jdk/blob/master/src/jdk.crypto.cryptoki/share/native/libj2pkcs11/p11_crypt.c#L365
    - https://github.com/openjdk/jdk/blob/master/src/jdk.crypto.cryptoki/share/native/libj2pkcs11/p11_crypt.c#L430
    - https://github.com/openjdk/jdk/blob/master/src/jdk.crypto.cryptoki/share/native/libj2pkcs11/p11_crypt.c#L493
  - In Java
    - IN the interface iaik.pkcs.pkcs11.wrapper.PKCS11 and the corresponding implementation 
      iaik.pkcs.pkcs11.wrapper.PKCS11Implementation, add new functions, as in 
      https://github.com/openjdk/jdk/blob/master/src/jdk.crypto.cryptoki/share/classes/sun/security/pkcs11/wrapper/PKCS11.java.
    - In the class org.xipki.pkcs11.wrapper.Session, add new functions, as in 
      https://github.com/openjdk/jdk/blob/master/src/jdk.crypto.cryptoki/share/classes/sun/security/pkcs11/Session.java
    - Add new JUnit tests.

## Licenses
This product includes software (IAIK PKCS#11 wrapper version 1.6.6) 
developed by Stiftung SIC which is licensed under "IAIK PKCS#11 Wrapper License".
All other parts are licensed under Apache License, version 2.
For details please refer to the file [LICENSE](LICENSE).

## Prerequisite
- JRE / JDK 8 or above

Use ipkcs11wrapper in your project
=====
- Maven  
  ```
  <dependency>
      <groupId>org.xipki</groupId>
      <artifactId>ipkcs11wrapper</artifactId>
      <version>1.0.0-SNAPSHOT</version>
  </dependency>
  ```

JUnit tests
=====
- Configure the library and PIN of your HSM module in the file `src/test/resources/pkcs11.properties`.
- `mvn test`  
   - To activate the speed tests use `-PspeedTests`
   - By default, the speed test will run with 2 threads, you can change the
     value via the Java property `speed.threads`, e.g.
    `-Dspeed.threads=5` to use 5 threads.
   - By default, the speed test will take 3 seconds, you can change the
     value via the Java property `speed.duration`, e.g.
    `-Dspeed.duration=10s` for 10 seconds.
