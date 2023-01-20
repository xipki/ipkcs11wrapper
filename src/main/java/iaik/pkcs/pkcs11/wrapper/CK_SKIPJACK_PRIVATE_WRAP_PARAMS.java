// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.

package iaik.pkcs.pkcs11.wrapper;

/**
 * class CK_SKIPJACK_PRIVATE_WRAP_PARAMS provides the parameters to the CKM_SKIPJACK_PRIVATE_WRAP
 * mechanism.
 * <p>
 * <B>PKCS#11 structure:</B>
 *
 * <PRE>
 *  typedef struct CK_SKIPJACK_PRIVATE_WRAP_PARAMS {
 *    CK_ULONG     ulPasswordLen;
 *    CK_BYTE_PTR  pPassword;
 *    CK_ULONG     ulPublicDataLen;
 *    CK_BYTE_PTR  pPublicData;
 *    CK_ULONG     ulPandGLen;
 *    CK_ULONG     ulQLen;
 *    CK_ULONG     ulRandomLen;
 *    CK_BYTE_PTR  pRandomA;
 *    CK_BYTE_PTR  pPrimeP;
 *    CK_BYTE_PTR  pBaseG;
 *    CK_BYTE_PTR  pSubprimeQ;
 *  } CK_SKIPJACK_PRIVATE_WRAP_PARAMS;
 * </PRE>
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Martin Schläffer (SIC)
 */
public class CK_SKIPJACK_PRIVATE_WRAP_PARAMS {

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_BYTE_PTR pPassword;
   * CK_ULONG ulPasswordLen;
   * </PRE>
   */
  public byte[] pPassword;

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_BYTE_PTR pPublicData;
   * CK_ULONG ulPublicDataLen;
   * </PRE>
   */
  public byte[] pPublicData;

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_BYTE_PTR pRandomA;
   * CK_ULONG ulRandomLen;
   * </PRE>
   */
  public byte[] pRandomA;

  /**
   * ulPAndGLen == pPrimeP.length == pBaseG.length
   * <p>
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_BYTE_PTR pPrimeP;
   * CK_ULONG ulPAndGLen;
   * </PRE>
   */
  public byte[] pPrimeP;

  /**
   * ulPAndGLen == pPrimeP.length == pBaseG.length <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_BYTE_PTR pBaseG;
   * CK_ULONG ulRandomLen;
   * </PRE>
   */
  public byte[] pBaseG;

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_BYTE_PTR pSubprimeQ;
   * CK_ULONG ulQLen;
   * </PRE>
   */
  public byte[] pSubprimeQ;

}
