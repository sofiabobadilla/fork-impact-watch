// Off-chain shapes Glamsterdam breaks: a fixed relayer gas limit and an old per-authorization budget.
import { createWalletClient, http } from "viem";

const RELAY_GAS_LIMIT = { gasLimit: 150_000 };
const PER_AUTH_GAS = 25_000n;

export async function delegate(client: ReturnType<typeof createWalletClient>, account: any, contract: `0x${string}`) {
  const authorization = await client.signAuthorization({ account, contractAddress: contract });
  return client.sendTransaction({
    account,
    to: account.address,
    authorizationList: [authorization],
    gas: 21000n + PER_AUTH_GAS,
  });
}

export { RELAY_GAS_LIMIT };
