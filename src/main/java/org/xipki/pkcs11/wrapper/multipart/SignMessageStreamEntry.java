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
public class SignMessageStreamEntry {

  private CkParams params;

  private InputStream data;

  public CkParams params() {
    return params;
  }

  public SignMessageStreamEntry params(CkParams params) {
    this.params = params;
    return this;
  }

  public InputStream data() {
    return data;
  }

  public SignMessageStreamEntry data(InputStream data) {
    this.data = data;
    return this;
  }

}
