// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.

package iaik.pkcs.pkcs11.wrapper;

/**
 * class CK_RC5_CBC_PARAMS is a structure that provides the parameters to the CKM_RC5_CBC and
 * CKM_RC5_CBC_PAD mechanisms.
 * <p>
 * <B>PKCS#11 structure:</B>
 *
 * <PRE>
 *  typedef struct CK_RC5_CBC_PARAMS {
 *    CK_ULONG ulWordsize;
 *    CK_ULONG ulRounds;
 *    CK_BYTE_PTR pIv;
 *    CK_ULONG ulIvLen;
 *  } CK_RC5_CBC_PARAMS;
 * </PRE>
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Martin Schläffer (SIC)
 */
public class CK_RC5_CBC_PARAMS {

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
   * CK_BYTE_PTR pIv;
   * CK_ULONG ulIvLen;
   * </PRE>
   */
  public byte[] pIv; /* pointer to IV */// FIXME: PTR

}
