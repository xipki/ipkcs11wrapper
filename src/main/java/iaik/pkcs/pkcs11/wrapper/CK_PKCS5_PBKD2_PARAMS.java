// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.

package iaik.pkcs.pkcs11.wrapper;

/**
 * class CK_PKCS5_PBKD2_PARAMS provides the parameters to the CKM_PKCS5_PBKD2 mechanism.
 * <p>
 * <B>PKCS#11 structure:</B>
 *
 * <PRE>
 * typedef struct CK_PKCS5_PBKD2_PARAMS {
 *   CK_PKCS5_PBKD2_SALT_SOURCE_TYPE             saltSource;
 *   CK_VOID_PTR                                 pSaltSourceData;
 *   CK_ULONG                                    ulSaltSourceDataLen;
 *   CK_ULONG                                    iterations;
 *   CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE  prf;
 *   CK_VOID_PTR                                 pPrfData;
 *   CK_ULONG                                    ulPrfDataLen;
 * } CK_PKCS5_PBKD2_PARAMS;
 * </PRE>
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Martin Schläffer (SIC)
 */
public class CK_PKCS5_PBKD2_PARAMS {

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE saltSource;
   * </PRE>
   */
  public long saltSource;

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_VOID_PTR pSaltSourceData;
   * CK_ULONG ulSaltSourceDataLen;
   * </PRE>
   */
  public byte[] pSaltSourceData;

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_ULONG iterations;
   * </PRE>
   */
  public long iterations;

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE prf;
   * </PRE>
   */
  public long prf;

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_VOID_PTR pPrfData;
   * CK_ULONG ulPrfDataLen;
   * </PRE>
   */
  public byte[] pPrfData;

}
