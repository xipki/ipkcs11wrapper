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

package org.xipki.pkcs11.parameters;

import iaik.pkcs.pkcs11.wrapper.CK_SALSA20_CHACHA20_POLY1305_PARAMS;
import org.xipki.pkcs11.Functions;

/**
 * This class encapsulates parameters for the Salsa20Chacha20 en/decryption.
 *
 * @author Patrick Schuster
 * @version 1.0
 */
public class Salsa20Chacha20Poly1305Parameters implements Parameters {

    protected byte[] nonce;
    protected byte[] aad;

    /**
     * Create a new Salsa20Chacha20Poly1305Parameters object with the given attributes.
     *
     * @param nonce nonce (This should be never re-used with the same key.) <br>
     *               length of nonce in bits (is 64 for original, 96 for IETF (only for
     *               chacha20) and 192 for xchacha20/xsalsa20 variant)
     * @param aad additional authentication data. This data is authenticated but not encrypted.
     *
     */
    public Salsa20Chacha20Poly1305Parameters(byte[] nonce, byte[] aad) {
        this.nonce = nonce;
        this.aad = aad;
    }

  /**
     * Get this parameters object as an object of the CK_SALSA20_CHACHA20_POLY1305_PARAMS class.
     *
     * @return This object as a CK_SALSA20_CHACHA20_POLY1305_PARAMS object.
     * @postconditions (result != null)
     */
    public Object getPKCS11ParamsObject() {
        CK_SALSA20_CHACHA20_POLY1305_PARAMS params = new CK_SALSA20_CHACHA20_POLY1305_PARAMS();
        params.pNonce = nonce;
        params.pAAD = aad;

        return params;
    }

    /**
     * Read the parameters from the PKCS11Object and overwrite the values into this object.
     *
     * @param obj Object to read the parameters from
     */
    public void setValuesFromPKCS11Object(Object obj) {
      this.nonce = ((CK_SALSA20_CHACHA20_POLY1305_PARAMS) obj).pNonce;
      this.aad = ((CK_SALSA20_CHACHA20_POLY1305_PARAMS) obj).pAAD;
    }

    /**
     * Returns the string representation of this object. Do not parse data from this string, it is for
     * debugging only.
     *
     * @return A string representation of this object.
     */
    public String toString() {
      return "Class: " + getClass().getName() +
          "\n  Nonce: " + Functions.toHex(nonce) + "\n  AAD: " + Functions.toHex(aad);
    }

}
