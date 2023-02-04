// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.speed.keygeneration;

/**
 * AES-192 speed test.
 */
public class AES192KeyGenSpeed extends AESKeyGenSpeed {

  @Override
  protected int getKeyByteLen() {
    return 24;
  }

}
