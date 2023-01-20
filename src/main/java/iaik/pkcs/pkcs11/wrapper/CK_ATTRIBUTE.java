// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.

package iaik.pkcs.pkcs11.wrapper;

/**
 * class CK_ATTRIBUTE includes the type, value and length of an attribute.
 * <p>
 * <B>PKCS#11 structure:</B>
 *
 * <PRE>
 * typedef struct CK_ATTRIBUTE {
 *   CK_ATTRIBUTE_TYPE  type;
 *   CK_VOID_PTR        pValue;
 *   CK_ULONG           sulValueLen;
 * } CK_ATTRIBUTE;
 * </PRE>
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Martin Schläffer (SIC)
 */
public class CK_ATTRIBUTE {

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_ATTRIBUTE_TYPE type;
   * </PRE>
   */
  public long type;

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_VOID_PTR pValue;
   * CK_ULONG ulValueLen;
   * </PRE>
   */
  public Object pValue;

}
