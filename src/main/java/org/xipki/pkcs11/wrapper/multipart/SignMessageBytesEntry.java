package org.xipki.pkcs11.wrapper.multipart;

import org.xipki.pkcs11.wrapper.params.CkParams;

public class SignMessageBytesEntry {

  private CkParams params;

  private byte[] data;

  public CkParams params() {
    return params;
  }

  public SignMessageBytesEntry params(CkParams params) {
    this.params = params;
    return this;
  }

  public byte[] data() {
    return data;
  }

  public SignMessageBytesEntry data(byte[] data) {
    this.data = data;
    return this;
  }

}
