// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.

package iaik.pkcs.pkcs11.wrapper;

/**
 * class .
 * <p>
 * <B>PKCS#11 structure:</B>
 *
 * <PRE>
 * typedef struct CK_DATE {
 *   CK_CHAR  year[4];
 *   CK_CHAR  month[2];
 *   CK_CHAR  day[2];
 * } CK_DATE;
 * </PRE>
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Martin Schläffer (SIC)
 */
public class CK_DATE {

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   *   CK_CHAR year[4];   - the year ("1900" - "9999")
   * </PRE>
   */
  public char[] year; /* the year ("1900" - "9999") */

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   *   CK_CHAR month[2];  - the month ("01" - "12")
   * </PRE>
   */
  public char[] month; /* the month ("01" - "12") */

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   *   CK_CHAR day[2];    - the day ("01" - "31")
   * </PRE>
   */
  public char[] day; /* the day ("01" - "31") */

}
