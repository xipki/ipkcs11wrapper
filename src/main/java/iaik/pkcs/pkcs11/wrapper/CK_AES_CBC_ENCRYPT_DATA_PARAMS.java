// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.

package iaik.pkcs.pkcs11.wrapper;

/**
 * The class CK_AES_CBC_ENCRYPT_DATA_PARAMS provides the parameters to the CKM_AES_CBC_ENCRYPT_DATA
 * mechanism.
 * <p>
 * <B>PKCS#11 structure:</B>
 *
 * <PRE>
 * typedef struct CK_AES_CBC_ENCRYPT_DATA_PARAMS {
 *   CK_BYTE      iv[16];
 *   CK_BYTE_PTR  pData;
 *   CK_ULONG     length;
 * } CK_AES_CBC_ENCRYPT_DATA_PARAMS;
 * </PRE>
 *
 * @author Karl Scheibelhofer (SIC)
 */
public class CK_AES_CBC_ENCRYPT_DATA_PARAMS {

  /**
   * The 16-byte initialization vector.
   * <p>
   * <B>PKCS#11:</B>
   *
   * <PRE>
   *   CK_BYTE iv[16];
   * </PRE>
   *
   */
  public byte[] iv;

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_BYTE_PTR pData;
   * CK_ULONG length;
   * </PRE>
   */
  public byte[] pData;

}
