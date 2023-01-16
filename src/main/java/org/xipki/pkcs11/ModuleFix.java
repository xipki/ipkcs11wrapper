package org.xipki.pkcs11;

class ModuleFix {

  private Boolean ecPointFixNeeded;

  private Boolean ecdsaSignatureFixNeeded;

  private Boolean sm2SignatureFixNeeded;

  private Boolean getSessionInfoSupported;

  public Boolean getEcPointFixNeeded() {
    return ecPointFixNeeded;
  }

  public void setEcPointFixNeeded(Boolean ecPointFixNeeded) {
    this.ecPointFixNeeded = ecPointFixNeeded;
  }

  public Boolean getEcdsaSignatureFixNeeded() {
    return ecdsaSignatureFixNeeded;
  }

  public void setEcdsaSignatureFixNeeded(Boolean ecdsaSignatureFixNeeded) {
    this.ecdsaSignatureFixNeeded = ecdsaSignatureFixNeeded;
  }

  public Boolean getSm2SignatureFixNeeded() {
    return sm2SignatureFixNeeded;
  }

  public void setSm2SignatureFixNeeded(Boolean sm2SignatureFixNeeded) {
    this.sm2SignatureFixNeeded = sm2SignatureFixNeeded;
  }

  public Boolean getGetSessionInfoSupported() {
    return getSessionInfoSupported;
  }

  public void setGetSessionInfoSupported(Boolean getSessionInfoSupported) {
    this.getSessionInfoSupported = getSessionInfoSupported;
  }

}
