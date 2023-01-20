// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.

package iaik.pkcs.pkcs11.wrapper;

/**
 * class CK_MECHANISM_INFO provides information about a particular mechanism.
 * <p>
 * <B>PKCS#11 structure:</B>
 *
 * <PRE>
 * typedef struct CK_MECHANISM_INFO {
 *   CK_ULONG  ulMinKeySize;
 *   CK_ULONG  ulMaxKeySize;
 *   CK_FLAGS  flags;
 * } CK_MECHANISM_INFO;
 * </PRE>
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Martin Schläffer (SIC)
 */
public class CK_MECHANISM_INFO {
  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_ULONG ulMinKeySize;
   * </PRE>
   */
  public long ulMinKeySize;

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_ULONG ulMaxKeySize;
   * </PRE>
   */
  public long ulMaxKeySize;

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_FLAGS flags;
   * </PRE>
   */
  public long flags;

}
