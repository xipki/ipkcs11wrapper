// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.

package iaik.pkcs.pkcs11.wrapper;

/**
 * class CK_PBE_PARAMS provides all of the necessary information required byte the CKM_PBE
 * mechanisms and the CKM_PBA_SHA1_WITH_SHA1_HMAC mechanism.
 * <p>
 * <B>PKCS#11 structure:</B>
 *
 * <PRE>
 * typedef struct CK_PBE_PARAMS {
 *   CK_CHAR_PTR pInitVector;
 *   CK_CHAR_PTR pPassword;
 *   CK_ULONG ulPasswordLen;
 *   CK_CHAR_PTR pSalt;
 *   CK_ULONG ulSaltLen;
 *   CK_ULONG ulIteration;
 * } CK_PBE_PARAMS;
 * </PRE>
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Martin Schläffer (SIC)
 */
public class CK_PBE_PARAMS {

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_CHAR_PTR pInitVector;
   * </PRE>
   */
  public char[] pInitVector;

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_CHAR_PTR pPassword;
   * CK_ULONG ulPasswordLen;
   * </PRE>
   */
  public char[] pPassword;

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   *   CK_CHAR_PTR pSalt
   *   CK_ULONG ulSaltLen;
   * </PRE>
   */
  public char[] pSalt;

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_ULONG ulIteration;
   * </PRE>
   */
  public long ulIteration;

}
