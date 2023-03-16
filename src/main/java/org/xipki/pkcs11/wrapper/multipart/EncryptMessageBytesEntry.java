package org.xipki.pkcs11.wrapper.multipart;

import org.xipki.pkcs11.wrapper.params.CkParams;

public class EncryptMessageBytesEntry {

  private CkParams params;

  private byte[] associatedData;

  private byte[] plaintext;

  public CkParams params() {
    return params;
  }

  public EncryptMessageBytesEntry params(CkParams params) {
    this.params = params;
    return this;
  }

  public byte[] associatedData() {
    return associatedData;
  }

  public EncryptMessageBytesEntry associatedData(byte[] associatedData) {
    this.associatedData = associatedData;
    return this;
  }

  public byte[] plaintext() {
    return plaintext;
  }

  public EncryptMessageBytesEntry ciphertext(byte[] plaintext) {
    this.plaintext = plaintext;
    return this;
  }
}
