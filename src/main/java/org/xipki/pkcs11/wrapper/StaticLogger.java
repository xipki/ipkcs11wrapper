// Copyright (c) 2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper;

/**
 * A logger provide static logging-methods.
 * @author Lijun Liao
 */
public class StaticLogger {

  private static Logger logger;

  public static void setLogger(Logger logger_) {
    logger = logger_;
  }

  public static void error(String format, Object... arguments) {
    if (logger != null) {
      logger.error(format, arguments);
    } else {
      print("ERROR", format, arguments);
    }
  }

  public static void warn(String format, Object... arguments) {
    if (logger != null) {
      logger.warn(format, arguments);
    } else {
      print("WARN", format, arguments);
    }
  }

  public static void info(String format, Object... arguments) {
    if (logger != null) {
      logger.info(format, arguments);
    } else {
      print("INFO", format, arguments);
    }
  }

  public static void debug(String format, Object... arguments) {
    if (logger != null) {
      logger.debug(format, arguments);
    }
  }

  public static void trace(String format, Object... arguments) {
    if (logger != null) {
      logger.trace(format, arguments);
    }
  }

  public static boolean isWarnEnabled() {
    return logger != null ? logger.isWarnEnabled() : true;
  }

  public static boolean isInfoEnabled() {
    return logger != null ? logger.isInfoEnabled() : true;
  }

  public static boolean isDebugEnabled() {
    return logger != null ? logger.isDebugEnabled() : false;
  }

  public static boolean isTraceEnabled() {
    return logger != null ? logger.isTraceEnabled() : false;
  }

  private static void print(String level, String format, Object... arguments) {
    StringBuilder sb = new StringBuilder();
    sb.append("[").append(level).append("] ");
    if (arguments == null || arguments.length == 0) {
      System.out.println(sb.append(format));
      return;
    }

    int fromIdx = 0;
    for (int i = 0; i < arguments.length; i++) {
      // search '{}' in format
      int idx = format.indexOf("{}", fromIdx);
      if (idx == -1) {
        // reach end
        sb.append(format, fromIdx, format.length());
        fromIdx = format.length();
        break;
      } else {
        sb.append(format, fromIdx, idx);
        sb.append(arguments[i]);
        fromIdx = idx + 2; // 2 = "{}".length().
      }
    }

    if (fromIdx < format.length()) {
      sb.append(format, fromIdx, format.length());
    }

    System.out.println(sb);
  }
}
