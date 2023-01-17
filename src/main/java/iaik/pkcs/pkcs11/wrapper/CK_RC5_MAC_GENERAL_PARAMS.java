// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.

package iaik.pkcs.pkcs11.wrapper;

/**
 * class CK_RC5_MAC_GENERAL_PARAMS provides the parameters to the CKM_RC5_MAC_GENERAL mechanism.
 * <p>
 * <B>PKCS#11 structure:</B>
 *
 * <PRE>
 * typedef struct CK_RC5_MAC_GENERAL_PARAMS {&nbsp;&nbsp;
 *   CK_ULONG ulWordsize;&nbsp;&nbsp;
 *   CK_ULONG ulRounds;&nbsp;&nbsp;
 *   CK_ULONG ulMacLength;&nbsp;&nbsp;
 * } CK_RC5_MAC_GENERAL_PARAMS;
 * </PRE>
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Martin Schläffer (SIC)
 */
public class CK_RC5_MAC_GENERAL_PARAMS {

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

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_ULONG ulMacLength;
   * </PRE>
   */
  public long ulMacLength; /* Length of MAC in bytes */

}
