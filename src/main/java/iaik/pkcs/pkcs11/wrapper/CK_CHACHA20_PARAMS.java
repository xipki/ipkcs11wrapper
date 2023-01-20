// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.

package iaik.pkcs.pkcs11.wrapper;

/**
 * class
 * <B>PKCS#11 structure:</B>
 * <PRE>
 * typedef struct CK_CHACHA20_PARAMS {
 *   CK_BYTE_PTR   pBlockCounter;
 *   CK_ULONG      blockCounterBits;
 *   CK_BYTE_PTR   pNonce;
 *   CK_ULONG      ulNonceBits;
 * } CK_CHACHA20_PARAMS;
 * </PRE>
 *
 * @author Patrick Schuster (SIC)
 */
public class CK_CHACHA20_PARAMS {
    /**
     * <B>PKCS#11:</B>
     * <PRE>
     * CK_BYTE_PTR pBlockCounter;
     * CK_ULONG ulBlockCounterBits
     * </PRE>
     */
    public byte[] pBlockCounter;

    /**
     * <B>PKCS#11:</B>
     * <PRE>
     * CK_BYTE_PTR pNonce;
     * CK_ULONG ulNonceBits
     * </PRE>
     */
    public byte[] pNonce;

}
