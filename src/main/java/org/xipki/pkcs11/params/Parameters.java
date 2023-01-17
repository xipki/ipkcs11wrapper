// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.params;

/**
 * Every Parameters-class implements this interface through which the module.
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Lijun Liao (xipki)
 */
public interface Parameters {

  /**
   * Get this parameters object as an object of the corresponding *_PARAMS
   * class of the iaik.pkcs.pkcs11.wrapper package.
   *
   * @return The object of the corresponding *_PARAMS class.
   */
  Object getPKCS11ParamsObject();

}
