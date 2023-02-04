// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper;

import java.io.*;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.StringTokenizer;

/**
 * This class do the following tasks.
 * <ul>
 *   <li>replace tab with 4 spaces</li>
 *   <li>delete trailing spaces</li>
 *   <li>reduce redundant empty lines</li>
 * </ul>
 */

public class CanonicalizeCode {

  private final String baseDir;

  private final int baseDirLen;

  private CanonicalizeCode(String baseDir) {
    this.baseDir = baseDir.endsWith(File.separator)
        ? baseDir : baseDir + File.separator;
    this.baseDirLen = this.baseDir.length();
  }

  public static void main(final String[] args) {
    try {
      String baseDir = args[0];
      CanonicalizeCode canonicalizer = new CanonicalizeCode(baseDir);
      canonicalizer.canonicalize();
      canonicalizer.checkWarnings();
    } catch (Exception ex) {
      ex.printStackTrace();
    }
  }

  private void canonicalize() throws Exception {
    canonicalizeDir(new File(baseDir));
  }

  private void canonicalizeDir(final File dir) throws Exception {
    File[] files = dir.listFiles();
    if (files == null) {
      return;
    }

    for (File file : files) {
      String filename = file.getName();
      if (file.isDirectory()) {
        if (!"target".equals(filename)
            && !"tbd".equals(filename)
            && !"dev".equals(filename)) {
          canonicalizeDir(file);
        }
      } else {
        int idx = filename.lastIndexOf('.');
        String extension = (idx == -1)
            ? filename : filename.substring(idx + 1);
        extension = extension.toLowerCase();

        if ("java".equals(extension)) {
          canonicalizeFile(file);
        }
      }
    }
  } // method canonicalizeDir

  private void canonicalizeFile(final File file) throws Exception {
    byte[] newLine = detectNewline(file);

    BufferedReader reader = new BufferedReader(new FileReader(file));

    ByteArrayOutputStream writer = new ByteArrayOutputStream();

    try {
      String line;
      boolean lastLineEmpty = false;

      while ((line = reader.readLine()) != null) {
        String canonicalizedLine = canonicalizeLine(line);
        boolean addThisLine = true;
        if (canonicalizedLine.isEmpty()) {
          if (!lastLineEmpty) {
            lastLineEmpty = true;
          } else {
            addThisLine = false;
          }
        } else {
          lastLineEmpty = false;
        }

        if (addThisLine) {
          writeLine(writer, newLine, canonicalizedLine);
        }
      } // end while
    } finally {
      writer.close();
      reader.close();
    }

    byte[] oldBytes = read(Files.newInputStream(file.toPath()));
    byte[] newBytes = writer.toByteArray();

    if (!Arrays.equals(oldBytes, newBytes)) {
      File newFile = new File(file.getPath() + "-new");
      save(file, newBytes);
      newFile.renameTo(file);
      System.out.println(file.getPath().substring(baseDirLen));
    }
  } // method canonicalizeFile

  /**
   * replace tab by 4 spaces, delete white spaces at the end.
   */
  private static String canonicalizeLine(String line) {
    if (line.trim().startsWith("//")) {
      // comments
      String nline = line.replace("\t", "    ");
      return removeTrailingSpaces(nline);
    }

    StringBuilder sb = new StringBuilder();
    int len = line.length();

    int lastNonSpaceCharIndex = 0;
    int index = 0;
    for (int i = 0; i < len; i++) {
      char ch = line.charAt(i);
      if (ch == '\t') {
        sb.append("    ");
        index += 4;
      } else if (ch == ' ') {
        sb.append(ch);
        index++;
      } else {
        sb.append(ch);
        index++;
        lastNonSpaceCharIndex = index;
      }
    }

    int numSpacesAtEnd = sb.length() - lastNonSpaceCharIndex;
    if (numSpacesAtEnd > 0) {
      sb.delete(lastNonSpaceCharIndex, sb.length());
    }

    return sb.toString();
  }

  private static String removeTrailingSpaces(final String line) {
    final int n = line.length();
    int idx;
    for (idx = n - 1; idx >= 0; idx--) {
      char ch = line.charAt(idx);
      if (ch != ' ') {
        break;
      }
    }
    return (idx == n - 1) ?  line : line.substring(0, idx + 1);
  } // method removeTrailingSpaces

  private static byte[] detectNewline(File file) throws IOException {
    InputStream is = Files.newInputStream(file.toPath());
    byte[] bytes = new byte[200];
    int size;
    try {
      size = is.read(bytes);
    } finally {
      is.close();
    }

    for (int i = 0; i < size - 1; i++) {
      byte bb = bytes[i];
      if (bb == '\n') {
        return new byte[]{'\n'};
      } else if (bb == '\r') {
        if (bytes[i + 1] == '\n') {
          return new byte[]{'\r', '\n'};
        } else {
          return new byte[]{'\r'};
        }
      }
    }

    return new byte[]{'\n'};
  }

  private static void writeLine(OutputStream out, byte[] newLine, String line)
      throws IOException {
    if (line != null && !line.isEmpty()) {
      out.write(line.getBytes());
    }
    out.write(newLine);
  }

  public static void save(final File file, final byte[] content)
      throws IOException {
    try (FileOutputStream out = new FileOutputStream(file)) {
      out.write(content);
    }
  }

  public static byte[] read(final InputStream in) throws IOException {
    try {
      ByteArrayOutputStream bout = new ByteArrayOutputStream();
      int readed;
      byte[] buffer = new byte[2048];
      while ((readed = in.read(buffer)) != -1) {
        bout.write(buffer, 0, readed);
      }

      return bout.toByteArray();
    } finally {
      try {
        in.close();
      } catch (IOException ex) {
        // Do nothing
      }
    }
  }

  private void checkWarnings() throws Exception {
    checkWarningsInDir(new File(baseDir));
  }

  private void checkWarningsInDir(final File dir) throws Exception {
    File[] files = dir.listFiles();
    if (files == null) {
      return;
    }

    for (File file : files) {
      if (file.isDirectory()) {
        if (!file.getName().equals("target")
            && !file.getName().equals("tbd")
            && !file.getName().equals("dev")) {
          checkWarningsInDir(file);
        }
      } else {
        String filename = file.getName();
        int idx = filename.lastIndexOf('.');
        String extension = (idx == -1)
            ? filename : filename.substring(idx + 1);
        extension = extension.toLowerCase();

        if ("java".equals(extension)) {
          checkWarningsInFile(file);
        }
      }
    }
  } // method checkWarningsInDir

  private void checkWarningsInFile(final File file) throws Exception {
    if (file.getName().equals("package-info.java")) {
      return;
    }

    BufferedReader reader = new BufferedReader(new FileReader(file));

    List<Integer> lineNumbers = new LinkedList<>();

    int lineNumber = 0;
    try {
      String line;
      while ((line = reader.readLine()) != null) {
        lineNumber++;
        if (lineNumber == 1 && line.startsWith("// #THIRDPARTY")) {
          return;
        }

        if (line.length() > 80 && !line.contains("http")) {
          lineNumbers.add(lineNumber);
          continue;
        }

        String trimmedLine = line.trim();
        if (trimmedLine.startsWith("* @param ")) {
          StringTokenizer tokenizer =
              new StringTokenizer(trimmedLine, " ");
          if (tokenizer.countTokens() != 3) {
            lineNumbers.add(lineNumber);
            continue;
          }
        }

        if (trimmedLine.startsWith("* @exception ")) {
          StringTokenizer tokenizer =
              new StringTokenizer(trimmedLine, " ");
          if (tokenizer.countTokens() != 3) {
            lineNumbers.add(lineNumber);
          }
        }

      } // end while
    } finally {
      reader.close();
    }

    if (!lineNumbers.isEmpty()) {
      System.out.println("Please check file "
          + file.getPath().substring(baseDirLen) + ": lines "
          + Arrays.toString(lineNumbers.toArray(new Integer[0])));
    }
  } // method checkWarningsInFile

}
