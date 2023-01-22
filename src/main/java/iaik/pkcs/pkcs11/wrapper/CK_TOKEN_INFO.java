// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.

package iaik.pkcs.pkcs11.wrapper;

/**
 * class CK_TOKEN_INFO provides information about a token.
 * <p>
 * <B>PKCS#11 structure:</B>
 *
 * <PRE>
 * typedef struct CK_TOKEN_INFO {
 *   CK_UTF8CHAR  label[32];
 *   CK_UTF8CHAR  manufacturerID[32];
 *   CK_UTF8CHAR  model[16];
 *   CK_CHAR      serialNumber[16];
 *   CK_FLAGS     flags;
 *   CK_ULONG     ulMaxSessionCount;
 *   CK_ULONG     ulSessionCount;
 *   CK_ULONG     ulMaxRwSessionCount;
 *   CK_ULONG     ulRwSessionCount;
 *   CK_ULONG     ulMaxPinLen;
 *   CK_ULONG     ulMinPinLen;
 *   CK_ULONG     ulTotalPublicMemory;
 *   CK_ULONG     ulFreePublicMemory;
 *   CK_ULONG     ulTotalPrivateMemory;
 *   CK_ULONG     ulFreePrivateMemory;
 *   CK_VERSION   hardwareVersion;
 *   CK_VERSION   firmwareVersion;
 *   CK_CHAR      utcTime[16];
 * } CK_TOKEN_INFO;
 *
 * </PRE>
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Martin Schläffer (SIC)
 */
public class CK_TOKEN_INFO {

  /*
   * label, manufacturerID, and model have been changed from CK_CHAR to CK_UTF8CHAR for v2.11.
   */
  /**
   * must be blank padded and only the first 32 chars will be used
   * <p>
   * <B>PKCS#11:</B>
   *
   * <PRE>
   *   CK_UTF8CHAR label[32];
   * </PRE>
   */
  public char[] label; /* blank padded */

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
   * must be blank padded and only the first 16 chars will be used
   * <p>
   * <B>PKCS#11:</B>
   *
   * <PRE>
   *   CK_UTF8CHAR model[16];
   * </PRE>
   */
  public char[] model; /* blank padded */

  /**
   * must be blank padded and only the first 16 chars will be used
   * <p>
   * <B>PKCS#11:</B>
   *
   * <PRE>
   *   CK_CHAR serialNumber[16];
   * </PRE>
   */
  public char[] serialNumber; /* blank padded */

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_FLAGS flags;
   * </PRE>
   */
  public long flags; /* see below */

  /*
   * ulMaxSessionCount, ulSessionCount, ulMaxRwSessionCount, ulRwSessionCount, ulMaxPinLen, and
   * ulMinPinLen have all been changed from CK_USHORT to CK_ULONG for v2.0
   */
  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_ULONG ulMaxSessionCount;
   * </PRE>
   */
  public long ulMaxSessionCount; /* max open sessions */

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_ULONG ulSessionCount;
   * </PRE>
   */
  public long ulSessionCount; /* sess. now open */

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_ULONG ulMaxRwSessionCount;
   * </PRE>
   */
  public long ulMaxRwSessionCount; /* max R/W sessions */

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_ULONG ulRwSessionCount;
   * </PRE>
   */
  public long ulRwSessionCount; /* R/W sess. now open */

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_ULONG ulMaxPinLen;
   * </PRE>
   */
  public long ulMaxPinLen; /* in bytes */

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_ULONG ulMinPinLen;
   * </PRE>
   */
  public long ulMinPinLen; /* in bytes */

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_ULONG ulTotalPublicMemory;
   * </PRE>
   */
  public long ulTotalPublicMemory; /* in bytes */

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_ULONG ulFreePublicMemory;
   * </PRE>
   */
  public long ulFreePublicMemory; /* in bytes */

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_ULONG ulTotalPrivateMemory;
   * </PRE>
   */
  public long ulTotalPrivateMemory; /* in bytes */

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_ULONG ulFreePrivateMemory;
   * </PRE>
   */
  public long ulFreePrivateMemory; /* in bytes */

  /*
   * hardwareVersion, firmwareVersion, and time are new for v2.0
   */
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

  /**
   * only the first 16 chars will be used <B>PKCS#11:</B>
   *
   * <PRE>
   *   CK_CHAR utcTime[16];
   * </PRE>
   */
  public char[] utcTime; /* time */

}
