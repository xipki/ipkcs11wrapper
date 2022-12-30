[![Build Status](https://secure.travis-ci.org/xipki/pkcs11wrapper2.svg)](http://travis-ci.org/xipki/pkcs11wrapper2)
[![GitHub release](https://img.shields.io/github/release/xipki/pkcs11wrapper2.svg)](https://github.com/xipki/pkcs11wrapper2/releases)
[![Github forks](https://img.shields.io/github/forks/xipki/pkcs11wrapper2.svg)](https://github.com/xipki/pkcs11wrapper2/network)
[![Github stars](https://img.shields.io/github/stars/xipki/pkcs11wrapper2.svg)](https://github.com/xipki/pkcs11wrapper2/stargazers)

[Original Readme.txt](IAIK.Readme.txt)

## Prerequisite
- JRE / JDK 8 (build 162+) or above

Use xipki/pkcs11wrapper in your project
=====
- Maven  
  ```
  <dependency>
      <groupId>org.xipki.iaik</groupId>
      <artifactId>sunpkcs11-wrapper2</artifactId>
      <version>1.0.0-SNAPSHOT</version>
  </dependency>
  ```
- Or copy the following jar file to your classpath:
  - [sunpkcs11-wrapper2-1.0.0.jar](https://github.com/xipki/pkcs11wrapper2/releases/download/v1.0.0/sunpkcs11-wrapper-1.0.0.jar)

JDK17 or above
=====
To use pkcs11wrapper in JDK 17 or above, please add the following java option:
```
--add-exports=jdk.crypto.cryptoki/sun.security.pkcs11.wrapper=ALL-UNNAMED
```

JUnit tests
=====
- Configure the library and PIN of your HSM module in the file `example/data/pkcs11.properties`.
- `mvn test`  
   - To activate the speed tests use `-PspeedTests`
   - By default the speed test will run with 2 threads, you can change the
     value via the Java property `speed.threads`, e.g.
    `-Dspeed.threads=5` to use 5 threads.
   - By default the speed test will take 3 seconds, you can change the
     value via the Java property `speed.duration`, e.g.
    `-Dspeed.duration=10s` for 10 seconds.

