// Copyright (c) 2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.params;

/**
 * CkParam with {@link ExtraParams} to provides extra information, e.g. the size of an EC curve's order.
 *
 * @author Lijun Liao (xipki)
 */
public class CkParamsWithExtra extends CkParams {

  private final CkParams ckParams;

  private final ExtraParams extraParams;

  /**
   * Constructor.
   * @param ckParams The real CkParams. May be null.
   * @param extraParams The extra parameters. May be null.
   */
  public CkParamsWithExtra(CkParams ckParams, ExtraParams extraParams) {
    this.ckParams = ckParams;
    this.extraParams = extraParams;
  }

  @Override
  protected Object getParams0() {
    return (ckParams == null) ? null : ckParams.getParams();
  }

  @Override
  protected int getMaxFieldLen() {
    return (ckParams == null) ? 0 : ckParams.getMaxFieldLen();
  }

  @Override
  public String toString(String indent) {
    return (ckParams == null) ? "NULL" : ckParams.toString(indent);
  }

  public ExtraParams getExtraParams() {
    return extraParams;
  }

}
