/* eslint-disable @typescript-eslint/no-unused-vars, @typescript-eslint/require-await */
import { Conflux } from '@onekeyfe/blockchain-libs/dist/provider/chains/cfx/conflux';
import { decrypt } from '@onekeyfe/blockchain-libs/dist/secret/encryptors/aes256';
import {
  PartialTokenInfo,
  UnsignedTx,
} from '@onekeyfe/blockchain-libs/dist/types/provider';
import { IJsonRpcRequest } from '@onekeyfe/cross-inpage-provider-types';
import Big from 'big.js';
import { Conflux as ConfluxJs } from 'js-conflux-sdk';
import Transaction from 'js-conflux-sdk/src/Transaction';
import { isNil } from 'lodash';

import debugLogger from '@onekeyhq/shared/src/logger/debugLogger';

import {
  NotImplemented,
  OneKeyInternalError,
  PendingQueueTooLong,
} from '../../../errors';
import {
  extractResponseError,
  fillUnsignedTx,
  fillUnsignedTxObj,
} from '../../../proxy';
import { Account, DBAccount, DBVariantAccount } from '../../../types/account';
import {
  HistoryEntryStatus,
  HistoryEntryTransaction,
} from '../../../types/history';
import {
  IApproveInfo,
  IEncodedTxAny,
  IEncodedTxUpdateOptions,
  IFeeInfo,
  IFeeInfoUnit,
  ISignCredentialOptions,
  ITransferInfo,
} from '../../../types/vault';
import { KeyringSoftwareBase } from '../../keyring/KeyringSoftwareBase';
import { VaultBase } from '../../VaultBase';
import { EVMTxDecoder } from '../evm/decoder/decoder';

import { KeyringHardware } from './KeyringHardware';
import { KeyringHd } from './KeyringHd';
import { KeyringImported } from './KeyringImported';
import { KeyringWatching } from './KeyringWatching';

// fields in https://docs.confluxnetwork.org/js-conflux-sdk/docs/how_to_send_tx#send-transaction-complete
export type IEncodedTxCfx = {
  from: string;
  to: string;
  value: string;
  data: string;
  gas?: string;
  // gasLimit is not a CFX transaction field.
  gasLimit?: string;
  gasPrice?: string;
  maxFeePerGas?: string;
  maxPriorityFeePerGas?: string;
  nonce?: number;
};

export enum IDecodedTxCfxType {
  NativeTransfer = 'NativeTransfer',
  TokenTransfer = 'TokenTransfer',
  TokenApprove = 'TokenApprove',
  Swap = 'Swap',
  NftTransfer = 'NftTransfer',
  Transaction = 'Transaction',
  ContractDeploy = 'ContractDeploy',
}

function decodeUnsignedTxFeeData(unsignedTx: UnsignedTx) {
  return {
    feeLimit: unsignedTx.feeLimit?.toFixed(),
    feePricePerUnit: unsignedTx.feePricePerUnit?.toFixed(),
  };
}

const PENDING_QUEUE_MAX_LENGTH = 10;

// TODO extends evm/Vault
export default class Vault extends VaultBase {
  private async getJsonRPCClient(): Promise<Conflux> {
    return (await this.engine.providerManager.getClient(
      this.networkId,
    )) as Conflux;
  }

  attachFeeInfoToEncodedTx(params: {
    encodedTx: any;
    feeInfoValue: IFeeInfoUnit;
  }): Promise<any> {
    return Promise.resolve(params.encodedTx);
  }

  decodeTx(encodedTx: IEncodedTxAny, payload?: any): Promise<any> {
    console.log(encodedTx, payload);
    console.log(Transaction);
    const transactionInfo = Transaction.decodeRaw(encodedTx);
    return Promise.resolve({
      ...transactionInfo,
      origin: ' ',
      fromAddress: transactionInfo.from,
      toAddress: transactionInfo.to,
      network: '123123',
    });
  }

  async buildEncodedTxFromTransfer(transferInfo: ITransferInfo): Promise<any> {
    const dbAccount = (await this.getDbAccount()) as DBVariantAccount;
    const actions = [];

    // token transfer
    if (transferInfo.token) {
      const token = await this.engine.getOrAddToken(
        this.networkId,
        transferInfo.token ?? '',
        true,
      );
      if (token) {
        // const hasStorageBalance = await this.isStorageBalanceAvailable({
        //   address: transferInfo.to,
        //   tokenAddress: transferInfo.token,
        // });
        // if (!hasStorageBalance) {
        //   actions.push(
        //     await this._buildStorageDepositAction({
        //       // amount: new BN(FT_MINIMUM_STORAGE_BALANCE ?? '0'), // TODO small storage deposit
        //       amount: new BN(FT_MINIMUM_STORAGE_BALANCE_LARGE ?? '0'),
        //       address: transferInfo.to,
        //     }),
        //   );
        // }
        // // token transfer
        // actions.push(
        //   await this._buildTokenTransferAction({
        //     transferInfo,
        //     token,
        //   }),
        // );
      }
    } else {
      // native token transfer
      // actions.push(
      //   await this._buildNativeTokenTransferAction({
      //     amount: transferInfo.amount,
      //   }),
      // );
    }
    // const pubKey = await this._getPublicKey({ prefix: false });
    // const publicKey = nearApiJs.utils.key_pair.PublicKey.from(pubKey);
    // // TODO Mock value here, update nonce and blockHash in buildUnsignedTxFromEncodedTx later
    // const nonce = 0; // 65899896000001
    // const blockHash = '91737S76o1EfWfjxUQ4k3dyD3qmxDQ7hqgKUKxgxsSUW';
    // const tx = nearApiJs.transactions.createTransaction(
    //   // 'c3be856133196da252d0f1083614cdc87a85c8aa8abeaf87daff1520355eec51',
    //   transferInfo.from,
    //   publicKey,
    //   transferInfo.token || transferInfo.to,
    //   nonce,
    //   actions,
    //   baseDecode(blockHash),
    // );
    // const txStr = serializeTransaction(tx);
    console.log(transferInfo);
    const conflux = new ConfluxJs({ 
      url: 'https://portal-test.confluxrpc.com',
      networkId: 1,
    });
    const transaction = new Transaction({
      to: transferInfo.to, // receiver address
      nonce: await conflux.getNextNonce(dbAccount.addresses[this.networkId]), // sender next nonce
      value: transferInfo.amount,
      gas: 21000,
      gasPrice: await conflux.getGasPrice(),
      epochHeight: await conflux.getEpochNumber(),
      storageLimit: 0,
      chainId: 1, // endpoint status.chainId
      data: '0x',
    });
    const PRIVATE_KEY =
      '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'; // sender private key
    transaction.sign(PRIVATE_KEY, 1); // sender privateKey
    console.log(transaction.serialize());
    return transaction.serialize();
  }

  buildEncodedTxFromApprove(approveInfo: IApproveInfo): Promise<any> {
    throw new Error('Method not implemented.');
  }

  updateEncodedTxTokenApprove(
    encodedTx: IEncodedTxAny,
    amount: string,
  ): Promise<IEncodedTxAny> {
    throw new Error('Method not implemented.');
  }

  async buildUnsignedTxFromEncodedTx(
    encodedTx: IEncodedTxCfx,
  ): Promise<UnsignedTx> {
    // const network = await this.getNetwork();
    // const dbAccount = await this.getDbAccount();
    debugLogger.sendTx(
      'buildUnsignedTxFromEncodedTx >>>> buildUnsignedTx',
      encodedTx,
      Transaction.decodeRaw(encodedTx),
    );
    console.log(encodedTx, Transaction.decodeRaw(encodedTx));
    return Promise.resolve(encodedTx);
  }

  private async getNextNonce(
    networkId: string,
    dbAccount: DBAccount,
  ): Promise<number> {
    const onChainNonce =
      (
        await this.engine.providerManager.getAddresses(networkId, [
          dbAccount.address,
        ])
      )[0]?.nonce ?? 0;

    // TODO: Although 100 history items should be enough to cover all the
    // pending transactions, we need to find a more reliable way.
    const historyItems = await this.engine.getHistory(
      networkId,
      dbAccount.id,
      undefined,
      false,
    );
    const nextNonce = Math.max(
      ...(await Promise.all(
        historyItems
          .filter((entry) => entry.status === HistoryEntryStatus.PENDING)
          .map((historyItem) =>
            EVMTxDecoder.getDecoder(this.engine)
              .decode((historyItem as HistoryEntryTransaction).rawTx)
              .then(({ nonce }) => (nonce ?? 0) + 1),
          ),
      )),
      onChainNonce,
    );

    if (nextNonce - onChainNonce >= PENDING_QUEUE_MAX_LENGTH) {
      throw new PendingQueueTooLong(PENDING_QUEUE_MAX_LENGTH);
    }

    return nextNonce;
  }

  async fetchFeeInfo(encodedTx: any): Promise<IFeeInfo> {
    const network = await this.getNetwork();
    const limit = '0';
    const price = '10';
    return {
      editable: false,
      nativeSymbol: network.symbol,
      nativeDecimals: network.decimals,
      symbol: network.feeSymbol,
      decimals: network.feeDecimals,
      limit,
      prices: [price],
      tx: null, // Must be null if network not support feeInTx
    };
  }

  keyringMap = {
    hd: KeyringHd,
    hw: KeyringHardware,
    imported: KeyringImported,
    watching: KeyringWatching,
  };

  private async _correctDbAccountAddress(dbAccount: DBAccount) {
    dbAccount.address = await this.engine.providerManager.selectAccountAddress(
      this.networkId,
      dbAccount,
    );
  }

  async simpleTransfer(
    payload: {
      to: string;
      value: string;
      tokenIdOnNetwork?: string;
      extra?: { [key: string]: any };
      gasPrice: string; // TODO remove gasPrice
      gasLimit: string;
    },
    options: ISignCredentialOptions,
  ) {
    debugLogger.engine('CFX simpleTransfer', payload);
    const { to, value, tokenIdOnNetwork, extra, gasLimit, gasPrice } = payload;
    const { networkId } = this;
    const network = await this.getNetwork();
    const dbAccount = await this.getDbAccount();
    // TODO what's this mean: correctDbAccountAddress
    await this._correctDbAccountAddress(dbAccount);
    const token = await this.engine.getOrAddToken(
      networkId,
      tokenIdOnNetwork ?? '',
      true,
    );
    const valueBN = new BigNumber(value);
    const extraCombined = {
      ...extra,
      feeLimit: new BigNumber(gasLimit),
      feePricePerUnit: new BigNumber(gasPrice),
    };
    // TODO buildUnsignedTx
    const unsignedTx = await this.engine.providerManager.buildUnsignedTx(
      networkId,
      fillUnsignedTx(network, dbAccount, to, valueBN, token, extraCombined),
    );
    console.log(unsignedTx, options);
    return this.signAndSendTransaction(unsignedTx, options);
  }

  async signAndSendTransaction(unsignedTx, options): Promise<string> {
    const dbAccount = await this.getDbAccount();
    const { password } = options;
    console.log(unsignedTx, options);
    const conflux = new ConfluxJs({
      url: 'https://portal-test.confluxrpc.com',
      networkId: 1,
    });
    const transactionInfo = Transaction.decodeRaw(unsignedTx);
    const transaction = new Transaction({
      ...transactionInfo,
    });
    const keyring = this.keyring as KeyringSoftwareBase;
    if (typeof password === 'undefined') {
      throw new OneKeyInternalError('password required');
    }

    const selectedAddress = dbAccount.addresses[this.networkId];
    console.log(keyring)
    const { [selectedAddress]: signer } = await keyring.getSigners(password, [
      selectedAddress,
    ]);
    console.log(signer);
    const privateKey = await this.getExportedCredential(options.password);
    transaction.sign(privateKey, 1);
    const transactionHash = await conflux.sendRawTransaction(
      transaction.serialize(),
    );
    return Promise.resolve(transactionHash);
  }

  async updateEncodedTx(
    encodedTx: IEncodedTxAny,
    payload: any,
    options: IEncodedTxUpdateOptions,
  ): Promise<IEncodedTxAny> {
    throw new Error('Method not implemented.');
  }

  override async getOutputAccount(): Promise<Account> {
    const dbAccount = (await this.getDbAccount()) as DBVariantAccount;
    const ret = {
      id: dbAccount.id,
      name: dbAccount.name,
      type: dbAccount.type,
      path: dbAccount.path,
      coinType: dbAccount.coinType,
      tokens: [],
      address: dbAccount.addresses?.[this.networkId] || '',
    };
    if (ret.address.length === 0) {
      // TODO: remove selectAccountAddress from proxy
      const address = await this.engine.providerManager.selectAccountAddress(
        this.networkId,
        dbAccount,
      );
      await this.engine.dbApi.addAccountAddress(
        dbAccount.id,
        this.networkId,
        address,
      );
      ret.address = address;
    }
    return ret;
  }

  async getExportedCredential(password: string): Promise<string> {
    const dbAccount = await this.getDbAccount();
    if (dbAccount.id.startsWith('hd-') || dbAccount.id.startsWith('imported')) {
      const keyring = this.keyring as KeyringSoftwareBase;
      const [encryptedPrivateKey] = Object.values(
        await keyring.getPrivateKeys(password),
      );
      return `0x${decrypt(password, encryptedPrivateKey).toString('hex')}`;
    }
    throw new OneKeyInternalError(
      'Only credential of HD or imported accounts can be exported',
    );
  }

  // Chain only functionalities below.

  override async proxyJsonRPCCall<T>(request: IJsonRpcRequest): Promise<T> {
    const client = await this.getJsonRPCClient();
    try {
      return await client.rpc.call(
        request.method,
        request.params as Record<string, any> | Array<any>,
      );
    } catch (e) {
      throw extractResponseError(e);
    }
  }

  createClientFromURL(url: string): Conflux {
    return new Conflux(url);
  }

  fetchTokenInfos(
    tokenAddresses: string[],
  ): Promise<Array<PartialTokenInfo | undefined>> {
    throw new NotImplemented();
  }
}
