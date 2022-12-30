/*
 *
 * Copyright (c) 2016 - 2019 Lijun Liao
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

package dev;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;

public class CodeGenerator {

  private static class CkmInfo {
    String name;
    boolean fullEncryptDecrypt;
    boolean singleEncryptDecrypt;
    boolean fullSignVerify;
    boolean singleSignVerify;
    boolean digest;
    boolean signVerifyRecover;
    boolean keypairGen;
    boolean keyGen;
    boolean wrapUnwrap;
    boolean derive;

    CkmInfo(String line) {
      int idx1 = 0;
      String[] tokens = new String[9];
      for (int i = 0; i < 8; i++) {
        int idx2 = line.indexOf(',', idx1);
        if (idx2 == -1) {
          throw new IllegalArgumentException("invalid CkmInfo '" + line + "'");
        }
        tokens[i] = line.substring(idx1, idx2);
        idx1 = idx2 + 1;
      }
      tokens[8] = line.substring(idx1);

      name = tokens[0];

      // EncryptDecrypt
      String token = tokens[1];
      if ("2".equals(token)) {
        singleEncryptDecrypt = true;
      } else if ("1".equals(token)) {
        fullEncryptDecrypt = true;
      } else if (!token.isEmpty()) {
        throw new IllegalArgumentException(
            "invalid EncryptDecrypt '" + token + "' in line '" + line + "'");
      }

      // SignVerify
      token = tokens[2];
      if ("2".equals(token)) {
        singleSignVerify = true;
      } else if ("1".equals(token)) {
        fullSignVerify = true;
      } else if (!token.isEmpty()) {
        throw new IllegalArgumentException(
            "invalid SignVerify '" + token + "' in line '" + line + "'");
      }

      // SRVR
      token = tokens[3];
      if ("1".equals(token)) {
        signVerifyRecover = true;
      } else if (!token.isEmpty()) {
        throw new IllegalArgumentException(
            "invalid SRVR '" + token + "' in line '" + line + "'");
      }

      // Digest
      token = tokens[4];
      if ("1".equals(token)) {
        digest = true;
      } else if (!token.isEmpty()) {
        throw new IllegalArgumentException(
            "invalid Digest '" + token + "' in line '" + line + "'");
      }

      // KeyPairGen
      token = tokens[5];
      if ("1".equals(token)) {
        keypairGen = true;
      } else if (!token.isEmpty()) {
        throw new IllegalArgumentException("invalid KeypairGen '"
            + token + "' in line '" + line + "'");
      }

      // KeyGen
      token = tokens[6];
      if ("1".equals(token)) {
        keyGen = true;
      } else if (!token.isEmpty()) {
        throw new IllegalArgumentException("invalid KeyGen '" + token
            + "' in line '" + line + "'");
      }

      // WrapUnwrap
      token = tokens[7];
      if ("1".equals(token)) {
        wrapUnwrap = true;
      } else if (!token.isEmpty()) {
        throw new IllegalArgumentException("invalid WrapUnwrap '"
            + token + "' in line '" + line + "'");
      }

      // Derive
      token = tokens[8];
      if ("1".equals(token)) {
        derive = true;
      } else if (!token.isEmpty()) {
        throw new IllegalArgumentException("invalid Derive '" + token
            + "' in line '" + line + "'");
      }

    }
  }

  public static final String DIR_RESOURCES = "src/dev/resources/";

  public static final String FILE_PKCS11_HEADER = DIR_RESOURCES + "pkcs11t.h";

  public static final String FILE_PKCS11_CKM_META
      = DIR_RESOURCES + "pkcs11t_ckm.csv";

  public static final String DIR_OUTPUT = "target/dev-output/";

  public static final String FILE_CONSTANTS = DIR_OUTPUT + "constants.txt";

  public static final String FILE_CKM_NAME = DIR_OUTPUT + "ckm.properties";

  public static final String FILE_CKR_NAME = DIR_OUTPUT + "ckr.properties";

  public static final String FILE_FULL_ENCRYPT_DECRYPT
      = DIR_OUTPUT + "fullEncryptDecrypt.txt";

  public static final String FILE_SINGLE_ENCRYPT_DECRYPT
      = DIR_OUTPUT + "singleEncryptDecrypt.txt";

  public static final String FILE_FULL_SIGN_VERIFY
      = DIR_OUTPUT + "fullSignVerify.txt";

  public static final String FILE_SINGLE_SIGN_VERIFY
      = DIR_OUTPUT + "singleSignVerify.txt";

  public static final String FILE_SIGNRECOVERVERIFY
      = DIR_OUTPUT + "signVerifyRecover.txt";

  public static final String FILE_KEYPAIRGEN = DIR_OUTPUT + "keypairgen.txt";

  public static final String FILE_KEYGEN = DIR_OUTPUT + "keygen.txt";

  public static final String FILE_DIGEST = DIR_OUTPUT + "digest.txt";

  public static final String FILE_WRAPUNWRAP = DIR_OUTPUT + "wrapUnwrap.txt";

  public static final String FILE_DERIVE = DIR_OUTPUT + "derive.txt";

  public static final String NEWLINE = "\n";

  public static void main(String[] args) {
    try {
      /*
      long a1 = PKCS11Constants.CKM_EC_KEY_PAIR_GEN;
      System.out.println(Functions.mechanismCodeToString(a1));
      System.out.println(Functions.mechanismCodeToString(
          PKCS11Constants.CKM_RC2_ECB));
      long a2 = Functions.mechanismStringToCode("CKM_ECDSA_KEY_PAIR_GEN");
      System.out.println(a1);
      System.out.println(a2);
      if (true) {
        return;
      }
      */

      File dir = new File(DIR_OUTPUT);
      dir.mkdirs();

      generateConstants();

      generateCkmInfo();

      System.out.println("Generated files are in " + dir.getAbsolutePath());
    } catch (Exception ex) {
      ex.printStackTrace();
    }
  }

  // CONSIDER THE DUPLICATED / DEPRECATED entries: check them
  private static void generateConstants() throws Exception {
    BufferedReader reader = new BufferedReader(
        new FileReader(FILE_PKCS11_HEADER));
    Map<Long, String> ckmCodeNameMap = new HashMap<>();
    Map<Long, List<String>> deprecatedCkmCodeNamesMap = new HashMap<>();
    Map<Long, String> ckrCodeNameMap = new HashMap<>();
    Map<Long, String> ckkCodeNameMap = new HashMap<>();
    Map<Long, String> ckaCodeNameMap = new HashMap<>();

    String line;
    while ((line = reader.readLine()) != null) {
      if (!line.trim().startsWith("#define")) {
        continue;
      }

      line = line.trim();
      StringTokenizer st = new StringTokenizer(line, " \t");
      if (st.countTokens() < 3) {
        continue;
      }

      boolean deprecated = line.toLowerCase().contains("deprecated");

      // skip token '#define'
      st.nextToken();
      String name = st.nextToken();
      String value = st.nextToken();

      if (value.equals("(~0UL)")) {
        value = "0xFFFFFFFF";
      } else if (value.endsWith("UL")) {
        value = value.substring(0, value.length() - 2);
      }

      boolean hex = false;
      if (value.startsWith("0x") || value.startsWith("0X")) {
        value = value.substring(2);
        hex = true;
      }
      Long longValue;
      try {
        longValue = Long.parseLong(value, hex ? 16 : 10);
      } catch (NumberFormatException ex) {
        continue;
      }

      if (name.startsWith("CKM_")) {
        Map<Long, String> map = ckmCodeNameMap;
        if (deprecated) {
          List<String> deprecatedNames =
              deprecatedCkmCodeNamesMap.get(longValue);
          if (deprecatedNames == null) {
            deprecatedNames = new LinkedList<>();
            deprecatedCkmCodeNamesMap.put(longValue, deprecatedNames);
          }
          deprecatedNames.add(name);

          if (!map.containsKey(longValue)) {
            map.put(longValue, name);
          }
        } else {
          map.put(longValue, name);
        }
      } else if (name.startsWith("CKR_")) {
        Map<Long, String> map = ckrCodeNameMap;
        if (deprecated) {
          if (!map.containsKey(longValue)) {
            map.put(longValue, name);
          }
        } else {
          map.put(longValue, name);
        }
      } else if (name.startsWith("CKK_")) {
        Map<Long, String> map = ckkCodeNameMap;
        if (deprecated) {
          if (!map.containsKey(longValue)) {
            map.put(longValue, name);
          }
        } else {
          map.put(longValue, name);
        }
      } else if (name.startsWith("CKA_")) {
        Map<Long, String> map = ckaCodeNameMap;
        if (deprecated) {
          if (!map.containsKey(longValue)) {
            map.put(longValue, name);
          }
        } else {
          map.put(longValue, name);
        }
      }
    }

    reader.close();

    reader = new BufferedReader(new FileReader(FILE_PKCS11_HEADER));
    BufferedWriter constantsWriter = new BufferedWriter(
        new FileWriter(FILE_CONSTANTS));
    while ((line = reader.readLine()) != null) {
      if (!line.trim().startsWith("#define CK")) {
        constantsWriter.write("  ");
        constantsWriter.write(line);
        constantsWriter.write(NEWLINE);
        continue;
      }

      line = line.trim();
      StringTokenizer st = new StringTokenizer(line, " \t");
      if (st.countTokens() < 3) {
        constantsWriter.write("  ");
        constantsWriter.write(line);
        constantsWriter.write(NEWLINE);
        System.out.println("Please check line: " + line);
        continue;
      }

      // skip token '#define'
      st.nextToken();
      String name = st.nextToken();
      String value = st.nextToken();

      if (value.equals("(~0UL)")) {
        value = "0xFFFFFFFF";
      } else if (value.endsWith("UL")) {
        value = value.substring(0, value.length() - 2);
      }

      boolean hex = false;
      if (value.startsWith("0x") || value.startsWith("0X")) {
        value = value.substring(2);
        hex = true;
      }
      Long longValue;
      try {
        longValue = Long.parseLong(value, hex ? 16 : 10);
      } catch (NumberFormatException ex) {
        longValue = null;
      }

      boolean deprecated = line.toLowerCase().contains("deprecated");
      if (deprecated) {
        if (longValue != null) {
          String name2 = null;
          if (name.startsWith("CKM_")) {
            name2 = ckmCodeNameMap.get(longValue);
          } else if (name.startsWith("CKR_")) {
            name2 = ckrCodeNameMap.get(longValue);
          } else if (name.startsWith("CKK_")) {
            name2 = ckkCodeNameMap.get(longValue);
          } else if (name.startsWith("CKA_")) {
            name2 = ckaCodeNameMap.get(longValue);
          }

          if (name2 != null && !name.equals(name2)) {
            constantsWriter.write("  /**");
            constantsWriter.write(NEWLINE);
            constantsWriter.write("   * Use " + name2 + " instead.");
            constantsWriter.write(NEWLINE);
            constantsWriter.write("   */");
            constantsWriter.write(NEWLINE);
          }
        }
        constantsWriter.write("  @Deprecated");
        constantsWriter.write(NEWLINE);
      }

      constantsWriter.write("  long " + formatName(name) + " = ");
      if (longValue != null) {
        constantsWriter.write("0x" + value + "L;");
      } else {
        constantsWriter.write(value);
      }
      constantsWriter.write(NEWLINE);
    }

    reader.close();

    constantsWriter.close();

    writeCkmConstants(FILE_CKM_NAME, ckmCodeNameMap,
        deprecatedCkmCodeNamesMap);
    writeCkrConstants(FILE_CKR_NAME, ckrCodeNameMap);
  }

  private static void generateCkmInfo() throws Exception {
    BufferedReader reader = new BufferedReader(
        new FileReader(FILE_PKCS11_CKM_META));

    BufferedWriter fullEncryptWriter =
        new BufferedWriter(new FileWriter(FILE_FULL_ENCRYPT_DECRYPT));
    BufferedWriter singleEncryptWriter =
        new BufferedWriter(new FileWriter(FILE_SINGLE_ENCRYPT_DECRYPT));

    BufferedWriter fullSignWriter =
        new BufferedWriter(new FileWriter(FILE_FULL_SIGN_VERIFY));
    BufferedWriter singleSignWriter =
        new BufferedWriter(new FileWriter(FILE_SINGLE_SIGN_VERIFY));

    BufferedWriter signRecoverWriter =
        new BufferedWriter(new FileWriter(FILE_SIGNRECOVERVERIFY));

    BufferedWriter keypairGenWriter =
        new BufferedWriter(new FileWriter(FILE_KEYPAIRGEN));

    BufferedWriter keyGenWriter =
        new BufferedWriter(new FileWriter(FILE_KEYGEN));

    BufferedWriter digestWriter =
        new BufferedWriter(new FileWriter(FILE_DIGEST));

    BufferedWriter wrapWriter =
        new BufferedWriter(new FileWriter(FILE_WRAPUNWRAP));

    BufferedWriter deriveWriter =
        new BufferedWriter(new FileWriter(FILE_DERIVE));

    String line;
    while ((line = reader.readLine()) != null) {
      line = line.trim();
      if (!line.startsWith("CKM_")) {
        continue;
      }

      CkmInfo ckmInfo = new CkmInfo(line);
      String text = ckmInfo.name + "," + NEWLINE;

      if (ckmInfo.fullEncryptDecrypt) {
        fullEncryptWriter.write(text);
      }

      if (ckmInfo.singleEncryptDecrypt) {
        singleEncryptWriter.write(text);
      }

      if (ckmInfo.fullSignVerify) {
        fullSignWriter.write(text);
      }

      if (ckmInfo.singleSignVerify) {
        singleSignWriter.write(text);
      }

      if (ckmInfo.signVerifyRecover) {
        signRecoverWriter.write(text);
      }

      if (ckmInfo.keypairGen) {
        keypairGenWriter.write(text);
      }

      if (ckmInfo.keyGen) {
        keyGenWriter.write(text);
      }

      if (ckmInfo.digest) {
        digestWriter.write(text);
      }

      if (ckmInfo.wrapUnwrap) {
        wrapWriter.write(text);
      }

      if (ckmInfo.derive) {
        deriveWriter.write(text);
      }
    }

    reader.close();
    fullEncryptWriter.close();
    singleEncryptWriter.close();
    fullSignWriter.close();
    singleSignWriter.close();
    signRecoverWriter.close();
    keypairGenWriter.close();
    keyGenWriter.close();
    wrapWriter.close();
    digestWriter.close();
    deriveWriter.close();
  }

  private static void writeCkrConstants(String fileName,
      Map<Long, String> codeNameMap) throws Exception {
    BufferedWriter writer = new BufferedWriter(new FileWriter(fileName));
    List<Long> codes = new ArrayList<>(codeNameMap.keySet());
    Collections.sort(codes);
    for (Long code : codes) {
      writer.write(formatValue(code));
      writer.write(" = ");
      writer.write(codeNameMap.get(code));
      writer.write(NEWLINE);
    }
    writer.close();
  }

  private static void writeCkmConstants(String fileName,
      Map<Long, String> codeNameMap,
      Map<Long, List<String>> deprecatedCodeNamesMap) throws Exception {
    BufferedWriter writer = new BufferedWriter(new FileWriter(fileName));
    List<Long> codes = new ArrayList<>(codeNameMap.keySet());
    Collections.sort(codes);
    for (Long code : codes) {
      writer.write(formatValue(code));
      writer.write(" = ");
      String name = codeNameMap.get(code);
      writer.write(name);
      List<String> deprecatedNames = deprecatedCodeNamesMap.get(code);
      if (deprecatedNames != null && !deprecatedNames.isEmpty()) {
        for (int i = 0; i < deprecatedNames.size(); i++) {
          String deprecatedName = deprecatedNames.get(i);
          if (!name.equals(deprecatedName)) {
            writer.write("," + deprecatedName);
          }
        }
      }

      writer.write(NEWLINE);
    }
    writer.close();
  }

  private static final String formatValue(long value) {
    String str = String.format("%8X", value);
    str = str.replace(' ', '0');
    return "0x" + str;
  }

  private static final String formatName(String name) {
    int suffixLen = 40 - name.length();
    if (suffixLen < 0) {
      System.err.println("negative suffixLen " + suffixLen);
    }

    StringBuilder buffer = new StringBuilder(40);
    buffer.append(name);
    for (int i = 0; i < suffixLen; i++) {
      buffer.append(' ');
    }
    return buffer.toString();
  }

}
