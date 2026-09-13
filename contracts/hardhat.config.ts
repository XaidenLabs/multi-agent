import hardhatToolboxViem from "@nomicfoundation/hardhat-toolbox-viem";
import { configVariable, defineConfig } from "hardhat/config";

export default defineConfig({
  plugins: [hardhatToolboxViem],
  solidity: {
    profiles: {
      default: {
        version: "0.8.28",
      },
      production: {
        version: "0.8.28",
        settings: {
          optimizer: {
            enabled: true,
            runs: 200,
          },
        },
      },
    },
  },
  networks: {
    monadTestnet: {
      type: "http",
      chainType: "l1",
      chainId: 10143,
      url: configVariable("MONAD_RPC_URL"),
      accounts: [configVariable("MONAD_PRIVATE_KEY")],
    },
  },
});
