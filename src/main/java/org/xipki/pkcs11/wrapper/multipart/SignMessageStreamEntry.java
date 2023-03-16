package org.xipki.pkcs11.wrapper.multipart;

import org.xipki.pkcs11.wrapper.params.CkParams;

import java.io.InputStream;

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
