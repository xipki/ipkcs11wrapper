// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.

package iaik.pkcs.pkcs11.wrapper;

/**
 * class CK_INFO provides general information about Cryptoki.
 * <B>PKCS#11 structure:</B>
 *
 * <PRE>
 *  typedef struct CK_INFO {
 *    CK_VERSION   cryptokiVersion;
 *    CK_UTF8CHAR  manufacturerID[32];
 *    CK_FLAGS     flags;
 *    CK_UTF8CHAR  libraryDescription[32];
 *    CK_VERSION   libraryVersion;
 *  } CK_INFO;
 * </PRE>
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Martin Schläffer (SIC)
 */
public class CK_INFO {

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_VERSION cryptokiVersion;
   * </PRE>
   */
  public CK_VERSION cryptokiVersion; /* Cryptoki interface ver */

  /**
   * must be blank padded - only the first 32 chars will be used
   * <B>PKCS#11:</B>
   *
   * <PRE>
   *   CK_UTF8CHAR manufacturerID[32];
   * </PRE>
   */
  public char[] manufacturerID; /* blank padded - only first 32 */
  /* chars will be used */

  /**
   * must be zero <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_FLAGS flags;
   * </PRE>
   */
  public long flags; /* must be zero */

  /* libraryDescription and libraryVersion are new for v2.0 */

  /**
   * must be blank padded - only the first 32 chars will be used
   * <B>PKCS#11:</B>
   *
  */
  public char[] libraryDescription; /* blank padded - only first 32 */
  /* chars will be used */

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_VERSION libraryVersion;
   * </PRE>
   */
  public CK_VERSION libraryVersion; /* version of library */

}
