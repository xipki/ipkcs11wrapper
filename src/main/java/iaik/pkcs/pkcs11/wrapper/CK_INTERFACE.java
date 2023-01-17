// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.

package iaik.pkcs.pkcs11.wrapper;

/**
 * @author Stiftung SIC (SIC)
 */
public class CK_INTERFACE {

    /**
     * <B>PKCS#11:</B>
     *
     * <PRE>
     * CK_CHAR *pInterfaceName;
     * </PRE>
     */
    public char[] interfaceName;

    /**
     * <B>PKCS#11:</B>
     *
     * <PRE>
     * CK_VOID_PTR pFunctionList;
     * </PRE>
     */
    Object functionList;

    /**
     * <B>PKCS#11:</B>
     *
     * <PRE>
     * CK_FLAGS flags;
     * </PRE>
     */
    public long flags;
}
