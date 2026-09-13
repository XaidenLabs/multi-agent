import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

export default buildModule("DadiengProtocolModule", (module) => {
  const admin = module.getAccount(0);
  const validatorThreshold = module.getParameter("validatorThreshold", 2);

  const registry = module.contract("DadiengRegistry", [admin]);
  const validation = module.contract("DadiengValidation", [registry, admin, validatorThreshold]);
  const rewards = module.contract("DadiengRewards", [registry, admin]);

  module.call(registry, "setValidationRegistry", [validation]);

  return { registry, validation, rewards };
});
