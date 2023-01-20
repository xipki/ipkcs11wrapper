// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.

package iaik.pkcs.pkcs11.wrapper;

/**
 * class CK_VERSION describes the version of a Cryptoki interface, a Cryptoki library, or an SSL
 * implementation, or the hardware or firmware version of a slot or token.
 * <p>
 * <B>PKCS#11 structure:</B>
 *
 * <PRE>
 * typedef struct CK_VERSION {
 *   CK_BYTE  major;
 *   CK_BYTE  minor;
 * } CK_VERSION;
 * </PRE>
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Martin Schläffer (SIC)
 */
public class CK_VERSION {

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_BYTE major;
   * </PRE>
   */
  public byte major; /* integer portion of version number */

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_BYTE minor;
   * </PRE>
   */
  public byte minor; /* 1/100ths portion of version number */

}
