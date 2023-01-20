// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.

package iaik.pkcs.pkcs11.wrapper;

/**
 * class CK_RC5_PARAMS provides the parameters to the CKM_RC5_ECB and CKM_RC5_MAC mechanisms.
 * <p>
 * <B>PKCS#11 structure:</B>
 *
 * <PRE>
 *  typedef struct CK_RC5_PARAMS {
 *    CK_ULONG  ulWordsize;
 *    CK_ULONG  ulRounds;
 *  } CK_RC5_PARAMS;
 * </PRE>
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Martin Schläffer (SIC)
 */
public class CK_RC5_PARAMS {

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_ULONG ulWordsize;
   * </PRE>
   */
  public long ulWordsize; /* wordsize in bits */

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_ULONG ulRounds;
   * </PRE>
   */
  public long ulRounds; /* number of rounds */

}
