// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.

package iaik.pkcs.pkcs11.wrapper;

/**
 * class CK_RC2_CBC_PARAMS provides the parameters to the CKM_RC2_CBC and CKM_RC2_CBC_PAD
 * mechanisms.
 * <p>
 * <B>PKCS#11 structure:</B>
 *
 * <PRE>
 *  typedef struct CK_RC2_CBC_PARAMS {
 *    CK_ULONG ulEffectiveBits;
 *    CK_BYTE iv[8];
 *  } CK_RC2_CBC_PARAMS;
 * </PRE>
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Martin Schläffer (SIC)
 */
public class CK_RC2_CBC_PARAMS {

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_ULONG ulEffectiveBits;
   * </PRE>
   */
  public long ulEffectiveBits; /* effective bits (1-1024) */

  /**
   * only the first 8 bytes will be used
   * <p>
   * <B>PKCS#11:</B>
   *
   * <PRE>
   *   CK_BYTE iv[8];
   * </PRE>
   */
  public byte[] iv; /* IV for CBC mode */

}
