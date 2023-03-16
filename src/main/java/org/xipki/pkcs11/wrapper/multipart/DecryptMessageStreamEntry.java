package org.xipki.pkcs11.wrapper.multipart;

import org.xipki.pkcs11.wrapper.params.CkParams;

import java.io.InputStream;
import java.io.OutputStream;

public class DecryptMessageStreamEntry {

  private CkParams params;

  private byte[] associatedData;

  private OutputStream outPlaintext;

  private InputStream inCiphertext;

  public CkParams params() {
    return params;
  }

  public DecryptMessageStreamEntry params(CkParams params) {
    this.params = params;
    return this;
  }

  public byte[] associatedData() {
    return associatedData;
  }

  public DecryptMessageStreamEntry associatedData(byte[] associatedData) {
    this.associatedData = associatedData;
    return this;
  }

  public OutputStream outPlaintext() {
    return outPlaintext;
  }

  public DecryptMessageStreamEntry outPlaintext(OutputStream outPlaintext) {
    this.outPlaintext = outPlaintext;
    return this;
  }

  public InputStream inCiphertext() {
    return inCiphertext;
  }

  public DecryptMessageStreamEntry inCiphertext(InputStream inCiphertext) {
    this.inCiphertext = inCiphertext;
    return this;
  }
}
