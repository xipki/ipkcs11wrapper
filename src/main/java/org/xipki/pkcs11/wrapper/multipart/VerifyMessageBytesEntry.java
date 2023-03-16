// Copyright (c) 2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.multipart;

import org.xipki.pkcs11.wrapper.params.CkParams;

/**
 * Parameter-pair for the multipart operation VerifyMessage. Input is byte[].
 *
 * @author Lijun Liao (xipki)
 */
public class VerifyMessageBytesEntry {

  private CkParams params;

  private byte[] data;

  private byte[] signature;

  public CkParams params() {
    return params;
  }

  public VerifyMessageBytesEntry params(CkParams params) {
    this.params = params;
    return this;
  }

  public byte[] data() {
    return data;
  }

  public VerifyMessageBytesEntry data(byte[] data) {
    this.data = data;
    return this;
  }

  public byte[] signature() {
    return signature;
  }

  public VerifyMessageBytesEntry signature(byte[] signature) {
    this.signature = signature;
    return this;
  }

}
