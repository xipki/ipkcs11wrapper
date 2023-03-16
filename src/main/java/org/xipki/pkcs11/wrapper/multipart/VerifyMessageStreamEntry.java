// Copyright (c) 2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.multipart;

import org.xipki.pkcs11.wrapper.params.CkParams;

import java.io.InputStream;

/**
 * Parameter-pair for the multipart operation VerifyMessage. Input is {@link InputStream}.
 *
 * @author Lijun Liao (xipki)
 */
public class VerifyMessageStreamEntry {

  private CkParams params;

  private InputStream data;

  private byte[] signature;

  public CkParams params() {
    return params;
  }

  public VerifyMessageStreamEntry params(CkParams params) {
    this.params = params;
    return this;
  }

  public InputStream data() {
    return data;
  }

  public VerifyMessageStreamEntry data(InputStream data) {
    this.data = data;
    return this;
  }

  public byte[] signature() {
    return signature;
  }

  public VerifyMessageStreamEntry signature(byte[] signature) {
    this.signature = signature;
    return this;
  }

}
