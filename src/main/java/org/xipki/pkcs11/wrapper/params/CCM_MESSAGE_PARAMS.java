// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.params;

import iaik.pkcs.pkcs11.wrapper.CK_CCM_MESSAGE_PARAMS;
import org.xipki.pkcs11.wrapper.PKCS11Constants;

/**
 * Represents the CCM_MESSAGE_PARAMS.
 *
 * @author Lijun Liao (xipki)
 */
public class CCM_MESSAGE_PARAMS extends CkParams implements CkMessageParams {

  private CK_CCM_MESSAGE_PARAMS params;

  /**
   * Create a new CCM_MESSAGE_PARAMS object with the given attributes.
   *
   * @param dataLen length of the data where 0 &le; ulDataLen &lt; 2^(8L).
   * @param nonce the nonce. length: 7 &le; ulNonceLen &le; 13.
   * @param nonceFixedBits number of bits of the original nonce to preserve when generating a <br>
   *                       new nonce. These bits are counted from the Most significant bits (to the right).
   * @param nonceGenerator Function used to generate a new nonce. Each nonce must be
   *                       unique for a given session.
   * @param mac CCM MAC returned on MessageEncrypt, provided on MessageDecrypt
   */
  public CCM_MESSAGE_PARAMS(int dataLen, byte[] nonce, long nonceFixedBits, long nonceGenerator, byte[] mac) {
    params = new CK_CCM_MESSAGE_PARAMS();
    params.ulDataLen = dataLen;
    params.pNonce = nonce;
    params.ulNonceFixedBits = nonceFixedBits;
    params.nonceGenerator = nonceGenerator;
    params.pMAC = mac;
  }

  @Override
  public CK_CCM_MESSAGE_PARAMS getParams() {
    if (module == null) {
      return params;
    }
    long newNOnceGenerator = module.genericToVendorCode(PKCS11Constants.Category.CKG_GENERATOR, params.nonceGenerator);
    if (newNOnceGenerator == params.nonceGenerator) {
      return params;
    }

    CK_CCM_MESSAGE_PARAMS params0 = new CK_CCM_MESSAGE_PARAMS();
    params0.ulDataLen = params.ulDataLen;
    params0.pNonce = params.pNonce;
    params0.ulNonceFixedBits = params.ulNonceFixedBits;
    params0.nonceGenerator = newNOnceGenerator;
    params0.pMAC = params.pMAC;
    return params0;
  }

  @Override
  public void setValuesFromPKCS11Object(Object obj) {
    this.params = (CK_CCM_MESSAGE_PARAMS) obj;
  }

  @Override
  protected int getMaxFieldLen() {
    return 16; // ulNonceFixedBits
  }

  @Override
  public String toString(String indent) {
    return indent + "CK_CCM_MESSAGE_PARAMS:" +
        val2Str(indent, "ulDataLen", params.ulDataLen) +
        ptr2str(indent, "pNonce", params.pNonce) +
        val2Str(indent, "nonceGenerator",
            codeToName(PKCS11Constants.Category.CKG_GENERATOR, params.nonceGenerator)) +
        val2Str(indent, "ulNonceFixedBits", params.ulNonceFixedBits) +
        ptr2str(indent, "pMAC", params.pMAC);
  }

}

