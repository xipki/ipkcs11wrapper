// Copyright (c) 2002 Graz University of Technology. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification,
// are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// 3. The end-user documentation included with the redistribution, if any, must
//    include the following acknowledgment:
//
//    "This product includes software developed by IAIK of Graz University of
//     Technology."
//
//    Alternately, this acknowledgment may appear in the software itself, if and
//    wherever such third-party acknowledgments normally appear.
//
// 4. The names "Graz University of Technology" and "IAIK of Graz University of
//    Technology" must not be used to endorse or promote products derived from this
//    software without prior written permission.
//
// 5. Products derived from this software may not be called "IAIK PKCS Wrapper",
//    nor may "IAIK" appear in their name, without prior written permission of
//    Graz University of Technology.
//
// THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESSED OR IMPLIED
// WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE LICENSOR BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
// OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
// OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
// ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

package iaik.pkcs.pkcs11.wrapper;

/**
 * The class CK_ECDSA_ECIES_PARAMS provides the parameters to the CKM_ECDSA_ECIES
 * mechanism.
 * <p>
 * <B>PKCS#11 structure:</B>
 *
 * <PRE>
 * typedef struct CK_ECDSA_ECIES_PARAMS // used by CKM_ECDSA_ECIES
 * {
 *     unsigned long int  hashAlg;          // hash algorithm used e.g. CKM_SHA_1
 *     unsigned long int  cryptAlg;         // crypt algorithm used for crypt/decrypt e.g. CKM_AES_ECB
 *     unsigned long int  cryptOpt;         // keysize of crypt algo (0 for CKM_ECDSA_ECIES_XOR)
 *     unsigned long int  macAlg;           // mac algorithm used e.g. CKM_SHA_1_HMAC
 *     unsigned long int  macOpt;           // keysize of mac algo (always 0)
 *     unsigned char     *pSharedSecret1;   // optional shared secret 1 included in hash calculation
 *     unsigned long int  ulSharetSecret1;  // length of shared secret 1
 *     unsigned char     *pSharedSecret2;   // optional shared secret 2 included in mac calculation
 *     unsigned long int  ulSharetSecret2;  // lentgh of shared secret 2
 * }
 * </PRE>
 *
 * @author Otto Touzil
 */
public class CK_ECDSA_ECIES_PARAMS {

    public long hashAlg;
    public long cryptAlg;
    public long cryptOpt;
    public long macAlg;
    public long macOpt;

    /**
     * optional shared secret 1 included in hash calculation.
     *
     * <B>PKCS#11:</B>
     *
     * <PRE>
     *  unsigned char     *pSharedSecret1;   // optional shared secret 1 included in hash calculation
     *  unsigned long int  ulSharetSecret1;  // length of shared secret 1
     * </PRE>
     *
     */
    public byte[] pSharedSecret1;

    /**
     * optional shared secret 2 included in hash calculation.
     *
     * <B>PKCS#11:</B>
     *
     * <PRE>
     *  unsigned char     *pSharedSecret2;   // optional shared secret 1 included in hash calculation
     *  unsigned long int  ulSharetSecret2;  // length of shared secret 1
     * </PRE>
     *
     */
    public byte[] pSharedSecret2;

}
