// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.

package iaik.pkcs.pkcs11.wrapper;

/**
 * class CK_SSL3_KEY_MAT_OUT contains the resulting key handles and initialization vectors after
 * performing a C_DeriveKey function with the CKM_SSL3_KEY_AND_MAC_DERIVE mechanism.
 * <p>
 * <B>PKCS#11 structure:</B>
 *
 * <PRE>
 * typedef struct CK_SSL3_KEY_MAT_OUT {
 *   CK_OBJECT_HANDLE  hClientMacSecret;
 *   CK_OBJECT_HANDLE  hServerMacSecret;
 *   CK_OBJECT_HANDLE  hClientKey;
 *   CK_OBJECT_HANDLE  hServerKey;
 *   CK_BYTE_PTR       pIVClient;
 *   CK_BYTE_PTR       pIVServer;
 * } CK_SSL3_KEY_MAT_OUT;
 * </PRE>
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Martin Schläffer (SIC)
 */
public class CK_SSL3_KEY_MAT_OUT {

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_OBJECT_HANDLE hClientMacSecret;
   * </PRE>
   */
  public long hClientMacSecret;

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_OBJECT_HANDLE hServerMacSecret;
   * </PRE>
   */
  public long hServerMacSecret;

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_OBJECT_HANDLE hClientKey;
   * </PRE>
   */
  public long hClientKey;

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_OBJECT_HANDLE hServerKey;
   * </PRE>
   */
  public long hServerKey;

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_BYTE_PTR pIVClient;
   * </PRE>
   */
  public byte[] pIVClient;

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_BYTE_PTR pIVServer;
   * </PRE>
   */
  public byte[] pIVServer;

}
