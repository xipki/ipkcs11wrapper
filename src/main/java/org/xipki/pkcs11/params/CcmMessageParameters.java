// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.params;

import iaik.pkcs.pkcs11.wrapper.CK_CCM_MESSAGE_PARAMS;
import org.xipki.pkcs11.Functions;

/**
 * This class encapsulates parameters for the AES-GCM message en/decryption.
 *
 * @author Patrick Schuster (SIC)
 * @author Lijun Liao (xipki)
 */
public class CcmMessageParameters implements MessageParameters {

  private int dataLen;
  private byte[] nonce;
  private long nonceFixedBits;
  private long nonceGenerator;
  private byte[] mac;

  /**
   * Create a new CcmMessageParameters object with the given attributes.
   *
   * @param dataLen length of the data where 0 &le; ulDataLen &lt; 2^(8L).
   * @param nonce the nonce. length: 7 &le; ulNonceLen &le; 13.
   * @param nonceFixedBits number of bits of the original nonce to preserve when generating a <br>
   *                     new nonce. These bits are counted from the Most significant bits (to the right).
   * @param nonceGenerator Function used to generate a new nonce. Each nonce must be
   *                          unique for a given session.
   * @param mac CCM MAC returned on MessageEncrypt, provided on MessageDecrypt
   */
  public CcmMessageParameters(int dataLen, byte[] nonce, long nonceFixedBits, long nonceGenerator, byte[] mac) {
    init(dataLen, nonce, nonceFixedBits, nonceGenerator, mac);
  }

  private void init(int dataLen, byte[] nonce, long nonceFixedBits, long nonceGenerator, byte[] mac) {
    this.dataLen = dataLen;
    this.nonce = nonce;
    this.nonceFixedBits = nonceFixedBits;
    this.nonceGenerator = nonceGenerator;
    this.mac = mac;
  }

  /**
   * Get this parameters object as an object of the CK_ECDH1_DERIVE_PARAMS class.
   *
   * @return This object as a CK_CCM_MESSAGE_PARAMS object.
   */
  public CK_CCM_MESSAGE_PARAMS getPKCS11ParamsObject() {
    CK_CCM_MESSAGE_PARAMS params = new CK_CCM_MESSAGE_PARAMS();
    params.ulDataLen = dataLen;
    params.pNonce = nonce;
    params.ulNonceFixedBits = nonceFixedBits;
    params.nonceGenerator = nonceGenerator;
    params.pMAC = mac;

    return params;
  }

  /**
   * Read the parameters from the PKCS11Object and overwrite the values into this object.
   *
   * @param obj Object to read the parameters from
   */
  @Override
  public void setValuesFromPKCS11Object(Object obj) {
    CK_CCM_MESSAGE_PARAMS params = (CK_CCM_MESSAGE_PARAMS) obj;
    init((int) params.ulDataLen, params.pNonce, params.ulNonceFixedBits, params.nonceGenerator, params.pMAC);
  }

  /**
   * Returns the string representation of this object. Do not parse data from this string, it is for
   * debugging only.
   *
   * @return A string representation of this object.
   */
  @Override
  public String toString() {
    return "Class: " + getClass().getName() + "\n  DataLen: " + dataLen + ", NonceFixedBits: " + nonceFixedBits +
        "\n  Nonce: " + Functions.toHex(nonce) + "\n  MAC: " + Functions.toHex(mac);
  }

}

