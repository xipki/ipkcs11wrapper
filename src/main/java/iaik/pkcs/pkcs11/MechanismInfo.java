// Copyright (c) 2002 Graz University of Technology. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
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
//    Technology" must not be used to endorse or promote products derived from
//    this software without prior written permission.
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

package iaik.pkcs.pkcs11;

import iaik.pkcs.pkcs11.wrapper.Functions;
import sun.security.pkcs11.wrapper.CK_MECHANISM_INFO;

import static iaik.pkcs.pkcs11.wrapper.PKCS11Constants.*;

/**
 * Objects of this class provide information about a certain mechanism that a
 * token implements.
 *
 * @author Karl Scheibelhofer
 * @version 1.0
 */
public class MechanismInfo {

  /**
   * The minimum key length supported by this algorithm.
   */
  protected long minKeySize;

  /**
   * The maximum key length supported by this algorithm.
   */
  protected long maxKeySize;

  /**
   * Contains all feature flags of this mechanism info.
   */
  protected long flags;

  /**
   * Default constructor. All member variables get the default value for their
   * type.
   */
  public MechanismInfo() { /* left empty intentionally */
  }

  /**
   * Constructor taking a CK_MECHANISM_INFO object as data source.
   *
   * @param ckMechanismInfo
   *          The CK_MECHANISM_INFO object that provides the data.
   */
  public MechanismInfo(CK_MECHANISM_INFO ckMechanismInfo) {
    Util.requireNonNull("ckMechanismInfo", ckMechanismInfo);
    this.minKeySize = ckMechanismInfo.ulMinKeySize;
    this.maxKeySize = ckMechanismInfo.ulMaxKeySize;
    this.flags = ckMechanismInfo.flags;
  }

  /**
   * Override equals to check for the equality of mechanism information.
   *
   * @param otherObject
   *          The other MechanismInfo object.
   * @return True, if other is an instance of this class and
   *         all member variables are equal.
   */
  @Override
  public boolean equals(Object otherObject) {
    if (this == otherObject) return true;
    else if (!(otherObject instanceof MechanismInfo)) return false;

    MechanismInfo other = (MechanismInfo) otherObject;
    return (minKeySize == other.minKeySize) && (maxKeySize == other.maxKeySize) && (flags == other.flags);
  }

  /**
   * Override hashCode to ensure that hashtable still works after overriding
   * equals.
   *
   * @return The hash code of this object. Taken from the mechanism code.
   */
  @Override
  public int hashCode() {
    return (int) (minKeySize ^ maxKeySize ^ flags);
  }

  /**
   * Get the minimum key length supported by this mechanism.
   *
   * @return The minimum key length supported by this mechanism.
   */
  public long getMinKeySize() {
    return minKeySize;
  }

  /**
   * Get the maximum key length supported by this mechanism.
   *
   * @return The maximum key length supported by this mechanism.
   */
  public long getMaxKeySize() {
    return maxKeySize;
  }

  /**
   * Check, if this mechanism is performed in hardware.
   *
   * @return True, if this mechanism is performed in hardware.
   */
  public boolean isHw() {
    return hasFlag(CKF_HW);
  }

  /**
   * Check, if this mechanism can be used for encryption.
   *
   * @return True, if this mechanism can be used for encryption.
   */
  public boolean isEncrypt() {
    return hasFlag(CKF_ENCRYPT);
  }

  /**
   * Check, if this mechanism can be used for decryption.
   *
   * @return True, if this mechanism can be used for decryption.
   */
  public boolean isDecrypt() {
    return hasFlag(CKF_DECRYPT);
  }

  /**
   * Check, if this mechanism can be used for digesting.
   *
   * @return True, if this mechanism can be used for digesting.
   */
  public boolean isDigest() {
    return hasFlag(CKF_DIGEST);
  }

  /**
   * Check, if this mechanism can be used for signing.
   *
   * @return True, if this mechanism can be used for signing.
   */
  public boolean isSign() {
    return hasFlag(CKF_SIGN);
  }

  /**
   * Check, if this mechanism can be used for signing with data recovery.
   *
   * @return True, if this mechanism can be used for signing with data
   *         recovery.
   */
  public boolean isSignRecover() {
    return hasFlag(CKF_SIGN_RECOVER);
  }

  /**
   * Check, if this mechanism can be used for verification.
   *
   * @return True, if this mechanism can be used for verification.
   */
  public boolean isVerify() {
    return hasFlag(CKF_VERIFY);
  }

  /**
   * Check, if this mechanism can be used for verification with data recovery.
   *
   * @return True, if this mechanism can be used for verification with data
   *         recovery.
   */
  public boolean isVerifyRecover() {
    return hasFlag(CKF_VERIFY_RECOVER);
  }

  /**
   * Check, if this mechanism can be used for secret key generation.
   *
   * @return True, if this mechanism can be used for secret key generation.
   */
  public boolean isGenerate() {
    return hasFlag(CKF_GENERATE);
  }

  /**
   * Check, if this mechanism can be used for key-pair generation.
   *
   * @return True, if this mechanism can be used for key-pair generation.
   */
  public boolean isGenerateKeyPair() {
    return hasFlag(CKF_GENERATE_KEY_PAIR);
  }

  /**
   * Check, if this mechanism can be used for key wrapping.
   *
   * @return True, if this mechanism can be used for key wrapping.
   */
  public boolean isWrap() {
    return hasFlag(CKF_WRAP);
  }

  /**
   * Check, if this mechanism can be used for key unwrapping.
   *
   * @return True, if this mechanism can be used for key unwrapping.
   */
  public boolean isUnwrap() {
    return hasFlag(CKF_UNWRAP);
  }

  /**
   * Check, if this mechanism can be used for key derivation.
   *
   * @return True, if this mechanism can be used for key derivation.
   */
  public boolean isDerive() {
    return hasFlag(CKF_DERIVE);
  }

  /**
   * Check, if this mechanism can be used with EC domain parameters over Fp.
   *
   * @return True, if this mechanism can be used with EC domain parameters
   *         over Fp.
   */
  public boolean isEcFp() {
    return hasFlag(CKF_EC_F_P);
  }

  /**
   * Check, if this mechanism can be used with EC domain parameters over F2m.
   *
   * @return True, if this mechanism can be used with EC domain parameters
   *         over F2m.
   */
  public boolean isEcF2m() {
    return hasFlag(CKF_EC_F_2M);
  }

  /**
   * Check, if this mechanism can be used with EC domain parameters of the
   * choice ecParameters.
   *
   * @return True, if this mechanism can be used with EC domain parameters of
   *         the choice ecParameters.
   */
  public boolean isEcEcParameters() {
    return hasFlag(CKF_EC_ECPARAMETERS);
  }

  /**
   * Check, if this mechanism can be used with EC domain parameters of the
   * choice namedCurve.
   *
   * @return True, if this mechanism can be used with EC domain parameters of
   *         the choice namedCurve.
   */
  public boolean isEcNamedCurve() {
    return hasFlag(CKF_EC_OID);
  }

  /**
   * Check, if this mechanism can be used with elliptic curve point
   * uncompressed.
   *
   * @return True, if this mechanism can be used with elliptic curve point
   *         uncompressed.
   */
  public boolean isEcUncompress() {
    return hasFlag(CKF_EC_UNCOMPRESS);
  }

  /**
   * Check, if this mechanism can be used with elliptic curve point
   * compressed.
   *
   * @return True, if this mechanism can be used with elliptic curve point
   *         compressed.
   */
  public boolean isEcCompress() {
    return hasFlag(CKF_EC_COMPRESS);
  }

  /**
   * Check, if there is an extension to the flags; false, if no extensions.
   * Must be false for this version of PKCS#11.
   *
   * @return False for this version.
   */
  public boolean isExtension() {
    return hasFlag(CKF_EXTENSION);
  }

  private boolean hasFlag(long mask) {
    return (flags & mask) != 0L;
  }

  /**
   * Set the minimum key length supported by this mechanism.
   *
   * @param minKeySize
   *          The minimum key length supported by this mechanism.
   */
  public void setMinKeySize(long minKeySize) {
    this.minKeySize = minKeySize;
  }

  /**
  /**
   * Set the maximum key length supported by this mechanism.
   *
   * @param maxKeySize
   *          The maximum key length supported by this mechanism.
   */
  public void setMaxKeySize(long maxKeySize) {
    this.maxKeySize = maxKeySize;
  }

  /**
   * Set, if this mechanism is performed in hardware.
   *
   * @param hw
   *          True, if this mechanism is performed in hardware.
   */
  public void setHw(boolean hw) {
    setFlagBit(CKF_HW, hw);
  }

  /**
   * Set if this mechanism can be used for encryption.
   *
   * @param encrypt
   *          True, if this mechanism can be used for encryption.
   */
  public void setEncrypt(boolean encrypt) {
    setFlagBit(CKF_ENCRYPT, encrypt);
  }

  /**
   * Set if this mechanism can be used for decryption.
   *
   * @param decrypt
   *          True, if this mechanism can be used for decryption.
   */
  public void setDecrypt(boolean decrypt) {
    setFlagBit(CKF_DECRYPT, decrypt);
  }

  /**
   * Set if this mechanism can be used for digesting.
   *
   * @param digest
   *          True, if this mechanism can be used for digesting.
   */
  public void setDigest(boolean digest) {
    setFlagBit(CKF_DIGEST, digest);
  }

  /**
   * Set if this mechanism can be used for signing.
   *
   * @param sign
   *          True, if this mechanism can be used for signing.
   */
  public void setSign(boolean sign) {
    setFlagBit(CKF_SIGN, sign);
  }

  /**
   * Set if this mechanism can be used for signing with data recovery.
   *
   * @param signRecover
   *          True, if this mechanism can be used for signing with data
   *          recovery.
   */
  public void setSignRecover(boolean signRecover) {
    setFlagBit(CKF_SIGN_RECOVER, signRecover);
  }

  /**
   * Set if this mechanism can be used for verification.
   *
   * @param verify
   *          True, if this mechanism can be used for verification.
   */
  public void setVerify(boolean verify) {
    setFlagBit(CKF_VERIFY, verify);
  }

  /**
   * Set if this mechanism can be used for verification with data recovery.
   *
   * @param verifyRecover
   *          True, if this mechanism can be used for verification with data
   *          recovery.
   */
  public void setVerifyRecover(boolean verifyRecover) {
    setFlagBit(CKF_VERIFY_RECOVER, verifyRecover);
  }

  /**
   * Set if this mechanism can be used for secret key generation.
   *
   * @param generate
   *          True, if this mechanism can be used for secret key generation.
   */
  public void setGenerate(boolean generate) {
    setFlagBit(CKF_GENERATE, generate);
  }

  /**
   * Set if this mechanism can be used for key-pair generation.
   *
   * @param generateKeyPair
   *          True, if this mechanism can be used for key-pair generation.
   */
  public void setGenerateKeyPair(boolean generateKeyPair) {
    setFlagBit(CKF_GENERATE_KEY_PAIR, generateKeyPair);
  }

  /**
   * Set if this mechanism can be used for key wrapping.
   *
   * @param wrap
   *          True, if this mechanism can be used for key wrapping.
   */
  public void setWrap(boolean wrap) {
    setFlagBit(CKF_WRAP, wrap);
  }

  /**
   * Set if this mechanism can be used for key unwrapping.
   *
   * @param unwrap
   *          True, if this mechanism can be used for key unwrapping.
   */
  public void setUnwrap(boolean unwrap) {
    setFlagBit(CKF_UNWRAP, unwrap);
  }

  /**
   * Set if this mechanism can be used for key derivation.
   *
   * @param derive
   *          True, if this mechanism can be used for key derivation.
   */
  public void setDerive(boolean derive) {
    setFlagBit(CKF_DERIVE, derive);
  }

  /**
   * Set if this mechanism can be used with EC domain parameters over Fp.
   *
   * @param ecFp
   *          True, if this mechanism can be used with EC domain parameters
   *          over Fp.
   */
  public void setEcFp(boolean ecFp) {
    setFlagBit(CKF_EC_F_P, ecFp);
  }

  /**
   * Set if this mechanism can be used with EC domain parameters over F2m.
   *
   * @param ecF2m
   *          True, if this mechanism can be used with EC domain parameters
   *          over F2m.
   */
  public void setEcF2m(boolean ecF2m) {
    setFlagBit(CKF_EC_F_2M, ecF2m);
  }

  /**
   * Set if this mechanism can be used with EC domain parameters of the
   * choice ecParameters.
   *
   * @param ecEcParameters
   *          True, if this mechanism can be used with EC domain parameters of
   *          the choice ecParameters.
   */
  public void setEcEcParameters(boolean ecEcParameters) {
    setFlagBit(CKF_EC_ECPARAMETERS, ecEcParameters);
  }

  /**
   * Set if this mechanism can be used with EC domain parameters of the
   * choice namedCurve.
   *
   * @param ecNamedCurve
   *          True, if this mechanism can be used with EC domain parameters of
   *          the choice namedCurve.
   */
  public void setEcNamedCurve(boolean ecNamedCurve) {
    setFlagBit(CKF_EC_OID, ecNamedCurve);
  }

  /**
   * Set if this mechanism can be used with elliptic curve point
   * uncompressed.
   *
   * @param ecUncompress
   *          True, if this mechanism can be used with elliptic curve point
   *          uncompressed.
   */
  public void setEcUncompress(boolean ecUncompress) {
    setFlagBit(CKF_EC_UNCOMPRESS, ecUncompress);
  }

  /**
   * Set if this mechanism can be used with elliptic curve point compressed.
   *
   * @param ecCompress
   *          True, if this mechanism can be used with elliptic curve point
   *          compressed.
   */
  public void setEcCompress(boolean ecCompress) {
    setFlagBit(CKF_EC_COMPRESS, ecCompress);
  }

  /**
   * Set if there is an extension to the flags; false, if no extensions.
   * Must be false for this version.
   *
   * @param extension
   *          False for this version.
   */
  public void setExtension(boolean extension) {
    setFlagBit(CKF_EXTENSION, extension);
  }

  /**
   * Check, if this mechanism info has those flags set to true, which are set
   * in the given mechanism info. This may be used as a simple check, if some
   * operations are supported.
   * This also checks the key length range, if they are specified in the given
   * mechanism object; i.e. if they are not zero.
   *
   * @param requiredFeatures
   *          The required features.
   * @return True, if the required features are supported.
   */
  public boolean supports(MechanismInfo requiredFeatures) {
    Util.requireNonNull("requiredFeatures", requiredFeatures);

    long requiredMaxKeySize = requiredFeatures.getMaxKeySize();
    if ((requiredMaxKeySize != 0) && (requiredMaxKeySize > maxKeySize)) {
      return false;
    }

    long requiredMinKeySize = requiredFeatures.getMinKeySize();
    if ((requiredMinKeySize != 0) && (requiredMinKeySize < minKeySize)) {
      return false;
    }

    return (requiredFeatures.flags & flags) == requiredFeatures.flags;
  }

  /**
   * Returns the string representation of this object.
   *
   * @return the string representation of this object
   */
  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder(200)
        .append("  Minimum Key-Size: ").append(minKeySize).append("\n  Maximum Key-Size: ").append(maxKeySize)
        .append("\n  Flags: 0x").append(Functions.toFullHex(flags));

    TokenInfo.addFlag(sb, "  hardware", isHw());
    TokenInfo.addFlag(sb, "  encrypt", isEncrypt());
    TokenInfo.addFlag(sb, "  decrypt", isDecrypt());
    TokenInfo.addFlag(sb, "  digest", isDigest());
    TokenInfo.addFlag(sb, "  sign", isSign());
    TokenInfo.addFlag(sb, "  sign recover", isSignRecover());
    TokenInfo.addFlag(sb, "  verify", isVerify());
    TokenInfo.addFlag(sb, "  verify recover", isVerifyRecover());
    TokenInfo.addFlag(sb, "  generate", isGenerate());
    TokenInfo.addFlag(sb, "  generate key-pair", isGenerateKeyPair());
    TokenInfo.addFlag(sb, "  wrap", isWrap());
    TokenInfo.addFlag(sb, "  unwrap", isUnwrap());
    TokenInfo.addFlag(sb, "  derive", isDerive());
    TokenInfo.addFlag(sb, "  EC F(p)", isEcFp());
    TokenInfo.addFlag(sb, "  EC F(2^m)", isEcF2m());
    TokenInfo.addFlag(sb, "  EC parameters", isEcEcParameters());
    TokenInfo.addFlag(sb, "  EC named curve", isEcNamedCurve());
    TokenInfo.addFlag(sb, "  EC uncompress", isEcUncompress());
    TokenInfo.addFlag(sb, "  EC compress", isEcCompress());
    TokenInfo.addFlag(sb, "  extension", isExtension());
    return sb.toString();
  }

  /**
   * Set the given feature flag(s) to the given value.
   *
   * @param flagMask
   *          The mask of the flag bit(s).
   * @param value
   *          True to set the flag(s), false to clear the flag(s).
   */
  private void setFlagBit(long flagMask, boolean value) {
    if (value) {
      flags |= flagMask;
    } else {
      flags &= ~flagMask;
    }
  }

}
