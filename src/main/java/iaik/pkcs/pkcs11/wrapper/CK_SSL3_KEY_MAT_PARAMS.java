// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.

package iaik.pkcs.pkcs11.wrapper;

/**
 * class CK_SSL3_KEY_MAT_PARAMS provides the parameters to the CKM_SSL3_KEY_AND_MAC_DERIVE
 * mechanism.
 * <p>
 * <B>PKCS#11 structure:</B>
 *
 * <PRE>
 * typedef struct CK_SSL3_KEY_MAT_PARAMS {
 *   CK_ULONG ulMacSizeInBits;
 *   CK_ULONG ulKeySizeInBits;
 *   CK_ULONG ulIVSizeInBits;
 *   CK_BBOOL bIsExport;
 *   CK_SSL3_RANDOM_DATA RandomInfo;
 *   CK_SSL3_KEY_MAT_OUT_PTR pReturnedKeyMaterial;
 * } CK_SSL3_KEY_MAT_PARAMS;
 * </PRE>
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Martin Schläffer (SIC)
 */
public class CK_SSL3_KEY_MAT_PARAMS {

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_ULONG ulMacSizeInBits;
   * </PRE>
   */
  public long ulMacSizeInBits;

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_ULONG ulKeySizeInBits;
   * </PRE>
   */
  public long ulKeySizeInBits;

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_ULONG ulIVSizeInBits;
   * </PRE>
   */
  public long ulIVSizeInBits;

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_BBOOL bIsExport;
   * </PRE>
   */
  public boolean bIsExport;

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_SSL3_RANDOM_DATA RandomInfo;
   * </PRE>
   */
  public CK_SSL3_RANDOM_DATA RandomInfo;

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_SSL3_KEY_MAT_OUT_PTR pReturnedKeyMaterial;
   * </PRE>
   */
  public CK_SSL3_KEY_MAT_OUT pReturnedKeyMaterial;

}
