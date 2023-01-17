// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.params;

/**
 * @author Stiftung SIC (SIC)
 * @author Lijun Liao (xipki)
 */
public interface MessageParameters extends Parameters{
  void setValuesFromPKCS11Object(Object obj);
}
