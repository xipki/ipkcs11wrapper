// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.

package iaik.pkcs.pkcs11.wrapper;

/**
 * class
 * <B>PKCS#11 structure:</B>
 * <PRE>
 * typedef struct CK_SALSA20_CHACHA20_POLY1305_PARAMS {
 *   CK_BYTE_PTR  pNonce;
 *   CK_ULONG     ulNonceLen;
 *   CK_BYTE_PTR  pAAD;
 *   CK_ULONG     ulAADLen;
 * } CK_SALSA20_CHACHA20_POLY1305_PARAMS;
 * </PRE>
 *
 * @author Patrick Schuster (SIC)
 */
public class CK_SALSA20_CHACHA20_POLY1305_PARAMS {
    /**
     * <B>PKCS#11:</B>
     * <PRE>
     * CK_BYTE_PTR pNonce;
     * CK_ULONG ulNonceLen;
     * </PRE>
     */
    public byte[] pNonce;

    /**
     * <B>PKCS#11:</B>
     * <PRE>
     * CK_BYTE_PTR pAAD;
     * CK_ULONG ulAADLen;
     * </PRE>
     */
    public byte[] pAAD;

}
