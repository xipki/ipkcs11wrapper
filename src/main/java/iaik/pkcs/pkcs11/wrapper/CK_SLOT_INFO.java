// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.

package iaik.pkcs.pkcs11.wrapper;

/**
 * class CK_SLOT_INFO provides information about a slot.
 * <p>
 * <B>PKCS#11 structure:</B>
 *
 * <PRE>
 *  typedef struct CK_SLOT_INFO {
 *    CK_UTF8CHAR  slotDescription[64];
 *    CK_UTF8CHAR  manufacturerID[32];
 *    CK_FLAGS     flags;
 *    CK_VERSION   hardwareVersion;
 *    CK_VERSION   firmwareVersion;
 *  } CK_SLOT_INFO;
 * </PRE>
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Martin Schläffer (SIC)
 */
public class CK_SLOT_INFO {

  /*
   * slotDescription and manufacturerID have been changed from CK_CHAR to CK_UTF8CHAR for v2.11.
   */
  /**
   * must be blank padded and only the first 64 chars will be used
   * <p>
   * <B>PKCS#11:</B>
   *
   * <PRE>
   *   CK_UTF8CHAR slotDescription[64];
   * </PRE>
   */
  public char[] slotDescription; /* blank padded */

  /**
   * must be blank padded and only the first 32 chars will be used
   * <p>
   * <B>PKCS#11:</B>
   *
   * <PRE>
   *   CK_UTF8CHAR manufacturerID[32];
   * </PRE>
   */
  public char[] manufacturerID; /* blank padded */

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_FLAGS flags;
   * </PRE>
   */
  public long flags;

  /* hardwareVersion and firmwareVersion are new for v2.0 */
  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_VERSION hardwareVersion;
   * </PRE>
   */
  public CK_VERSION hardwareVersion; /* version of hardware */

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_VERSION firmwareVersion;
   * </PRE>
   */
  public CK_VERSION firmwareVersion; /* version of firmware */

}
