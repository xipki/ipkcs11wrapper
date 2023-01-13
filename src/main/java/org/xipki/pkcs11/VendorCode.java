/*
 *
 * Copyright (c) 2022 - 2023 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.pkcs11;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;

/**
 * @author Lijun Liao (xipki)
 */
class VendorCode {

  private static class ConfBlock {
    private List<String> modulePaths;
    private List<String> manufacturerIDs;
    private List<String> descriptions;
    private List<String> versions;
    private final Map<String, String> nameToCodeMap = new HashMap<>();

    void validate() throws IOException {
      if (isEmpty(modulePaths) && isEmpty(manufacturerIDs) && isEmpty(descriptions)) {
        throw new IOException("invalid <vendorcode>-block");
      }
    }

    boolean matches(String modulePath, String manufacturerID, String libraryDescription, Version libraryVersion) {
      if ((!isEmpty(modulePaths)     && !contains(modulePaths,     Paths.get(modulePath).getFileName().toString())) ||
          (!isEmpty(manufacturerIDs) && !contains(manufacturerIDs, manufacturerID)) ||
          (!isEmpty(descriptions)    && !contains(descriptions,    libraryDescription))) {
        return false;
      }

      if (isEmpty(versions)) return true;

      int iVersion = ((0xFF & libraryVersion.getMajor()) << 8) + (0xFF & libraryVersion.getMinor());
      boolean match = false;
      for (String t : versions) {
        int idx = t.indexOf("-");
        int from = (idx == -1) ? toIntVersion(t) : toIntVersion(t.substring(0, idx));
        int to   = (idx == -1) ? from            : toIntVersion(t.substring(idx + 1));

        if (iVersion >= from && iVersion <= to) {
          match = true;
          break;
        }
      }

      return match;
    }

    private static int toIntVersion(String version) {
      StringTokenizer st = new StringTokenizer(version, ".");
      return (Integer.parseInt(st.nextToken()) << 8) + Integer.parseInt(st.nextToken());
    }

    private static boolean isEmpty(Collection<?> c) {
      return c == null || c.isEmpty();
    }

    private static boolean contains(List<String> list, String str) {
      str = str.toLowerCase(Locale.ROOT);
      for (String s : list) {
        if (str.contains(s)) return true;
      }
      return false;
    }
  }

  static VendorCode getVendorCode(String modulePath, String manufacturerID, String libraryDescription,
                                  Version libraryVersion) throws IOException {
    String confPath = System.getProperty("org.xipki.pkcs11.vendorcode.conf");
    InputStream in = (confPath != null) ? Files.newInputStream(Paths.get(modulePath))
        : VendorCode.class.getClassLoader().getResourceAsStream("org/xipki/pkcs11/vendorcode.conf");
    try (BufferedReader br = new BufferedReader(new InputStreamReader(in))) {
      while (true) {
        ConfBlock block = readVendorCodeBlock(br);
        if (block == null) break;

        // For better performance, this line should be in the if-block. But we put
        // it here explicitly to make sure that all vendorcode blocks ar configured correctly.
        VendorCode vendorCode = new VendorCode(block.nameToCodeMap);
        if (block.matches(modulePath, manufacturerID, libraryDescription, libraryVersion)) return vendorCode;
      }
    }

    return null;
  }

  private static ConfBlock readVendorCodeBlock(BufferedReader reader) throws IOException {
    boolean inBlock = false;
    String line;
    ConfBlock block = null;
    while ((line = reader.readLine()) != null) {
      line = line.trim();
      if (line.isEmpty() || line.charAt(0) == '#') continue;

      if (line.startsWith("<vendorcode>")) {
        block = new ConfBlock();
        inBlock = true;
      } else if (line.startsWith("</vendorcode>")) {
        block.validate();
        return block;
      } else if (inBlock) {
        if (line.startsWith("module.")) {
          int idx = line.indexOf(' ');
          if (idx == -1) continue;

          String value = line.substring(idx + 1).trim();
          if (value.isEmpty()) continue;

          String name = line.substring(0, idx).trim();
          List<String> textList = Arrays.asList(value.toLowerCase(Locale.ROOT).split(":"));
          if (name.equalsIgnoreCase("module.path")) {
            block.modulePaths = textList;
          } else if (name.equalsIgnoreCase("module.mid")) {
            block.manufacturerIDs = textList;
          } else if (name.equalsIgnoreCase("module.description")) {
            block.descriptions = textList;
          } else if (name.equalsIgnoreCase("module.version")) {
            block.versions = textList;
          }
        } else if (line.startsWith("CKK_") || line.startsWith("CKM_")) {
          int idx = line.indexOf(' ');
          if (idx != -1) {
            block.nameToCodeMap.put(line.substring(0, idx).trim(), line.substring(idx + 1).trim());
          }
        }
      }
    }

    return block;
  }

  private final Map<Long, Long> ckkGenericToVendorMap = new HashMap<>();

  private final Map<Long, Long> ckkVendorToGenericMap = new HashMap<>();

  private final Map<Long, Long> ckmGenericToVendorMap = new HashMap<>();

  private final Map<Long, Long> ckmVendorToGenericMap = new HashMap<>();

  private VendorCode(Map<String, String> nameToCodeMap) {
    for (Map.Entry<String, String> entry : nameToCodeMap.entrySet()) {
      String name = entry.getKey().toUpperCase(Locale.ROOT);
      String valueStr = entry.getValue().toUpperCase(Locale.ROOT);
      boolean hex = valueStr.startsWith("0X");
      long vendorCode = hex ? Long.parseLong(valueStr.substring(2), 16) : Long.parseLong(valueStr);

      if (name.startsWith("CKK_VENDOR_")) {
        long genericCode = PKCS11Constants.nameToCode(PKCS11Constants.Category.CKK, name);
        if (genericCode == -1) throw new IllegalStateException("unknown name in vendorcode block: " + name);

        ckkGenericToVendorMap.put(genericCode, vendorCode);
      } else if (name.startsWith("CKM_VENDOR_")) {
        long genericCode = PKCS11Constants.ckmNameToCode(name);
        if (genericCode == -1) throw new IllegalStateException("unknown name in vendorcode block: " + name);

        ckmGenericToVendorMap.put(genericCode, vendorCode);
      } else {
        throw new IllegalStateException("Unknown name in vendorcode block: " + name);
      }
    }

    for (Map.Entry<Long, Long> m : ckkGenericToVendorMap.entrySet()) {
      ckkVendorToGenericMap.put(m.getValue(), m.getKey());
    }

    for (Map.Entry<Long, Long> m : ckmGenericToVendorMap.entrySet()) {
      ckmVendorToGenericMap.put(m.getValue(), m.getKey());
    }
  }

  long ckkGenericToVendor(long genericCode) {
    return ckkGenericToVendorMap.getOrDefault(genericCode, genericCode);
  }

  long ckkVendorToGeneric(long vendorCode) {
    return ckkVendorToGenericMap.getOrDefault(vendorCode, vendorCode);
  }

  long ckmGenericToVendor(long genericCode) {
    return ckmGenericToVendorMap.getOrDefault(genericCode, genericCode);
  }

  long ckmVendorToGeneric(long vendorCode) {
    return ckmVendorToGenericMap.getOrDefault(vendorCode, vendorCode);
  }

}
