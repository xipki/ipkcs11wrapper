// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.params;

import org.xipki.pkcs11.Functions;

/**
 * Every Parameters-class implements this interface through which the module.
 *
 * @author Lijun Liao (xipki)
 */
public abstract class CkParams {

  /**
   * Get this parameters object as an object of the corresponding *_PARAMS
   * class of the iaik.pkcs.pkcs11.wrapper package.
   *
   * @return The object of the corresponding *_PARAMS class.
   */
  public abstract Object getParams();

  protected String ptrToString(byte[] data) {
    return data == null ? "<NULL_PTR>" : Functions.toString(data);
  }

  protected String ptrToString(char[] data) {
    return data == null ? "<NULL_PTR>" : new String(data);
  }

  protected static <T> T requireNonNull(String paramName, T param) {
    if (param == null) throw new NullPointerException("Argument '" + paramName + "' must not be null.");

    return param;
  }

}
