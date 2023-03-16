// Copyright (c) 2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.multipart;

import org.xipki.pkcs11.wrapper.params.CkParams;

import java.io.InputStream;
import java.io.OutputStream;

/**
 * Parameter-pair for the multipart operation EncryptMessage. The plain text is an {@link InputStream},
 * and the cipher text is an {@link OutputStream}.
 *
 * @author Lijun Liao (xipki)
 */
public class EncryptMessageStreamEntry {

  private CkParams params;

  private byte[] associatedData;

  private OutputStream outCiphertext;

  private InputStream inPlaintext;

  public CkParams params() {
    return params;
  }

  public EncryptMessageStreamEntry params(CkParams params) {
    this.params = params;
    return this;
  }

  public byte[] associatedData() {
    return associatedData;
  }

  public EncryptMessageStreamEntry associatedData(byte[] associatedData) {
    this.associatedData = associatedData;
    return this;
  }

  public OutputStream outCiphertext() {
    return outCiphertext;
  }

  public EncryptMessageStreamEntry outCiphertext(OutputStream outCiphertext) {
    this.outCiphertext = outCiphertext;
    return this;
  }

  public InputStream inPlaintext() {
    return inPlaintext;
  }

  public EncryptMessageStreamEntry inPlaintext(InputStream inPlaintext) {
    this.inPlaintext = inPlaintext;
    return this;
  }
}
