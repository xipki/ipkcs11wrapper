// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.

package iaik.pkcs.pkcs11.wrapper;

/**
 * class CK_KEY_WRAP_SET_OAEP_PARAMS provides the parameters to the CKM_KEY_WRAP_SET_OAEP mechanism.
 * <p>
 * <B>PKCS#11 structure:</B>
 *
 * <PRE>
 * typedef struct CK_KEY_WRAP_SET_OAEP_PARAMS {
 *   CK_BYTE      bBC;
 *   CK_BYTE_PTR  pX;
 *   CK_ULONG     ulXLen;
 * } CK_KEY_WRAP_SET_OAEP_PARAMS;
 * </PRE>
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Martin Schläffer (SIC)
 */
public class CK_KEY_WRAP_SET_OAEP_PARAMS {

  /**
   * block contents byte <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_BYTE bBC;
   * </PRE>
   */
  public byte bBC; /* block contents byte */

  /**
   * extra data <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_BYTE_PTR pX;
   * CK_ULONG ulXLen;
   * </PRE>
   */
  public byte[] pX; /* extra data */

}
