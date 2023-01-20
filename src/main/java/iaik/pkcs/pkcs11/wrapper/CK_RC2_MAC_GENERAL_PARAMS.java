// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.

package iaik.pkcs.pkcs11.wrapper;

/**
 * class CK_RC2_MAC_GENERAL_PARAMS provides the parameters to the CKM_RC2_MAC_GENERAL mechanism.
 * <p>
 * <B>PKCS#11 structure:</B>
 *
 * <PRE>
 * typedef struct CK_RC2_MAC_GENERAL_PARAMS {
 *   CK_ULONG  ulEffectiveBits;
 *   CK_ULONG  ulMacLength;
 * } CK_RC2_MAC_GENERAL_PARAMS;
 * </PRE>
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Martin Schläffer (SIC)
 */
public class CK_RC2_MAC_GENERAL_PARAMS {

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_ULONG ulEffectiveBits;
   * </PRE>
   */
  public long ulEffectiveBits; /* effective bits (1-1024) */

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_ULONG ulMacLength;
   * </PRE>
   */
  public long ulMacLength; /* Length of MAC in bytes */

}
