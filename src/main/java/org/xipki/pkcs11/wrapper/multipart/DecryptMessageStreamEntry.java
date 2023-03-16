// Copyright (c) 2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.multipart;

import org.xipki.pkcs11.wrapper.params.CkParams;

import java.io.InputStream;
import java.io.OutputStream;

/**
 * Parameter-pair for the multipart operation DecryptMessage. The cipher text is an {@link InputStream},
 * and the plain text is an {@link OutputStream}.
 *
 * @author Lijun Liao (xipki)
 */
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
