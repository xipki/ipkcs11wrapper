// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package demo.pkcs.pkcs11.wrapper.basics;

import demo.pkcs.pkcs11.wrapper.TestBase;
import org.junit.Test;
import org.xipki.pkcs11.*;

import java.util.List;

import static org.xipki.pkcs11.PKCS11Constants.CKF_TOKEN_INITIALIZED;
import static org.xipki.pkcs11.PKCS11Constants.ckmCodeToName;

/**
 * This demo program lists information about a library, the available slots, the
 * available tokens and the objects on them. It takes the name of the module and
 * the absolute path to the shared library of the IAIK PKCS#11 Wrapper and
 * prompts the user PIN. If the user PIN is not available, the program will list
 * only public objects but no private objects; i.e. as defined in PKCS#11 for
 * public read-only sessions.
 */
public class GetModuleInfo extends TestBase {

  @Test
  public void main() throws PKCS11Exception {
    PKCS11Module pkcs11Module = getModule();
    ModuleInfo moduleInfo = pkcs11Module.getInfo();
    LOG.info("##################################################");
    LOG.info("{}", moduleInfo);
    LOG.info("##################################################");
    LOG.info("getting list of all slots");
    Slot[] slots = pkcs11Module.getSlotList(false);

    for (Slot slot : slots) {
      LOG.info("___________________________________________________");
      SlotInfo slotInfo = slot.getSlotInfo();
      LOG.info("Slot with ID: {}", slot.getSlotID());
      LOG.info("--------------------------------------------------");
      LOG.info("{}", slotInfo);
      LOG.info("___________________________________________________");
    }

    LOG.info("##################################################");
    LOG.info("getting list of all tokens");
    Slot[] slotsWithToken = pkcs11Module.getSlotList(true);
    Token[] tokens = new Token[slotsWithToken.length];

    for (int i = 0; i < slotsWithToken.length; i++) {
      LOG.info("___________________________________________________");
      tokens[i] = slotsWithToken[i].getToken();
      TokenInfo tokenInfo = tokens[i].getTokenInfo();
      LOG.info("Token in slot with ID: {}", tokens[i].getSlot().getSlotID());
      LOG.info("{}", tokenInfo);

      LOG.info("supported Mechanisms:");
      List<Long> supportedMechanisms = getMechanismList(tokens[i]);
      for (long supportedMechanism : supportedMechanisms) {
        MechanismInfo mechanismInfo = tokens[i].getMechanismInfo(supportedMechanism);
        LOG.info("--------------------------------------------------");
        LOG.info("Mechanism: {}\n{}", ckmCodeToName(supportedMechanism), mechanismInfo);
      }
    }

    LOG.info("##################################################");
    LOG.info("listing objects on tokens");
    for (Token token : tokens) {
      LOG.info("___________________________________________________");
      TokenInfo tokenInfo = token.getTokenInfo();
      LOG.info("listing objects for token: {}", tokenInfo);
      if (!tokenInfo.hasFlagBit(CKF_TOKEN_INITIALIZED)) {
        LOG.info("token not initialized yet");
        continue;
      }

      Session session = openReadOnlySession(token);
      try {
        main0(session);
      } finally {
        session.closeSession();
      }
    }
  }

  private void main0(Session session) throws PKCS11Exception {
    SessionInfo sessionInfo = session.getSessionInfo();
    LOG.info("using session: {}", sessionInfo);

    int limit = 0, counter = 0;

    session.findObjectsInit(null);
    long[] objects = session.findObjects(1);
    if (0 < objects.length) {
      counter++;
    }

    while (objects.length > 0 && (0 == limit || counter < limit)) {
      long object = objects[0];
      LOG.info("--------------------------------------------------");
      LOG.info("Object with handle: {}", object);
      LOG.info("--------------------------------------------------");
      objects = session.findObjects(1);
      counter++;
    }
    session.findObjectsFinal();

    LOG.info("___________________________________________________");
    LOG.info("found {} objects on this token", counter);
    LOG.info("___________________________________________________");
  }
}
