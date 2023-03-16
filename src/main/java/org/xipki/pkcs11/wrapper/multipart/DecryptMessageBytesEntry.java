package org.xipki.pkcs11.wrapper.multipart;

import org.xipki.pkcs11.wrapper.params.CkParams;

public class DecryptMessageBytesEntry {

  private CkParams params;

  private byte[] associatedData;

  private byte[] ciphertext;

  public CkParams params() {
    return params;
  }

  public DecryptMessageBytesEntry params(CkParams params) {
    this.params = params;
    return this;
  }

  public byte[] associatedData() {
    return associatedData;
  }

  public DecryptMessageBytesEntry associatedData(byte[] associatedData) {
    this.associatedData = associatedData;
    return this;
  }

  public byte[] ciphertext() {
    return ciphertext;
  }

  public DecryptMessageBytesEntry ciphertext(byte[] ciphertext) {
    this.ciphertext = ciphertext;
    return this;
  }
}
