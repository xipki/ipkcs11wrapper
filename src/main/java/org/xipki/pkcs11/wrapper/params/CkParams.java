// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.params;

import org.xipki.pkcs11.wrapper.Functions;
import org.xipki.pkcs11.wrapper.PKCS11Constants;
import org.xipki.pkcs11.wrapper.PKCS11Module;

import java.util.Arrays;

/**
 * Every Parameters-class implements this interface through which the module.
 *
 * @author Lijun Liao (xipki)
 */
public abstract class CkParams {

  protected PKCS11Module module;

  /**
   * Get this parameters object as an object of the corresponding *_PARAMS
   * class of the iaik.pkcs.pkcs11.wrapper package.
   *
   * @return The object of the corresponding *_PARAMS class.
   */
  public abstract Object getParams();

  protected abstract int getMaxFieldLen();

  public abstract String toString(String indent);

  public void setModule(PKCS11Module module) {
    this.module = module;
  }

  @Override
  public final String toString() {
    return toString("");
  }

  protected String ptr2str(String indent, String name, Object value) {
    String prefix = "\n" + indent + "  ";
    if (!name.isEmpty()) {
      prefix += formatFieldName(name) + ": ";
    }

    if (value == null) {
      return prefix + "<NULL_PTR>";
    } else if (value instanceof byte[]) {
      char[] spaceIndent = new char[prefix.length() - 1]; // -1: the leading '\n'.
      Arrays.fill(spaceIndent, ' ');
      byte[] bytes = (byte[]) value;
      return prefix + "byte[" + bytes.length + "]\n" + Functions.toString(new String(spaceIndent), bytes);
    } else if (value instanceof  char[]) {
      return prefix + new String((char[]) value);
    } else {
      return prefix + value;
    }
  }

  protected String val2Str(String indent, String name, Object value) {
    String prefix = "\n" + indent + "  ";
    if (!name.isEmpty()) {
      prefix += formatFieldName(name) + ": ";
    }
    return prefix + value;
  }

  private String formatFieldName(String name) {
    int maxFieldNameLen = getMaxFieldLen();
    if (name.length() >= maxFieldNameLen) {
      return name;
    }
    char[] prefix = new char[maxFieldNameLen - name.length()];
    Arrays.fill(prefix, ' ');
    return new String(prefix) + name;
  }

  protected String codeToName(PKCS11Constants.Category category, long code) {
    String name = PKCS11Constants.codeToName(category, code);
    if (module != null) {
      long code2 = module.genericToVendorCode(category, code);
      if (code != code2) {
        name += " (native: " + module.codeToName(category, code2) + ")";
      }
    }
    return name;
  }

  protected static <T> T requireNonNull(String paramName, T param) {
    return Functions.requireNonNull(paramName, param);
  }

}
