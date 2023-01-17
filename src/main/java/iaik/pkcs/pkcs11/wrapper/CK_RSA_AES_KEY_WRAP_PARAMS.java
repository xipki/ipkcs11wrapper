// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.

package iaik.pkcs.pkcs11.wrapper;

/**
 * class
 * <B>PKCS#11 structure:</B>
 * <PRE>
 typedef struct CK_RSA_AES_KEY_WRAP_PARAMS {
 CK_ULONG                      ulAESKeyBits;
 CK_RSA_PKCS_OAEP_PARAMS_PTR   pOAEPParams;
 } CK_RSA_AES_KEY_WRAP_PARAMS;
 * </PRE>
 *
 * @author Patrick Schuster (SIC)
 */
public class CK_RSA_AES_KEY_WRAP_PARAMS {
    /**
     * <B>PKCS#11:</B>
     * <PRE>
     * CK_ULONG ulAESKeyBits
     * </PRE>
     */
    public long ulAESKeyBits;

    /**
     * <B>PKCS#11:</B>
     * <PRE>
     * CK_RSA_PKCS_OAEP_PARAMS_PTR   pOAEPParams;
     * </PRE>
     */
    public CK_RSA_PKCS_OAEP_PARAMS pOAEPParams;
}
