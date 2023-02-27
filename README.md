## Licenses
This product includes software (IAIK PKCS#11 wrapper version 1.6.8) 
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
      <version>1.0.1</version>
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
