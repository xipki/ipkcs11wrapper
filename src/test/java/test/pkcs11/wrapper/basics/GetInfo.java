// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.basics;

import org.junit.Test;
import org.xipki.pkcs11.wrapper.*;
import test.pkcs11.wrapper.TestBase;

import java.util.List;

import static org.xipki.pkcs11.wrapper.PKCS11Constants.ckmCodeToName;

/**
 * This demo program lists information about a library, the available slots, the
 * available tokens and the objects on them. It takes the name of the module and
 * the absolute path to the shared library of the IAIK PKCS#11 Wrapper and
 * prompts the user PIN. If the user PIN is not available, the program will list
 * only public objects but no private objects; i.e. as defined in PKCS#11 for
 * public read-only sessions.
 */
public class GetInfo extends TestBase {

  @Test
  public void main() throws TokenException {
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
      LOG.info("--------------------------------------------------");
      LOG.info("{}", tokenInfo);

      LOG.info("supported Mechanisms:");
      List<Long> supportedMechanisms = getMechanismList(tokens[i]);
      for (long supportedMechanism : supportedMechanisms) {
        LOG.info("--------------------------------------------------");
        MechanismInfo mechanismInfo = tokens[i].getMechanismInfo(supportedMechanism);
        LOG.info("--------------------------------------------------");
        LOG.info("Mechanism: {}\n{}", ckmCodeToName(supportedMechanism), mechanismInfo);
      }
      LOG.info("___________________________________________________");
    }
  }

}
