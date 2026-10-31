import { Config, waitForTransactionReceipt } from '@wagmi/core'

/** Waits for confirmation and rejects transactions that reverted after simulation. */
export const waitForSuccessfulTransactionReceipt = async (
  config: Config,
  parameters: Parameters<typeof waitForTransactionReceipt>[1]
) => {
  const receipt = await waitForTransactionReceipt(config, parameters)
  if (receipt.status !== 'success') {
    throw new Error(`Transaction ${receipt.transactionHash} reverted`)
  }
  return receipt
}
