/* eslint-disable @typescript-eslint/no-unused-vars, @typescript-eslint/require-await */
import { Conflux } from '@onekeyfe/blockchain-libs/dist/provider/chains/cfx/conflux';
import { decrypt } from '@onekeyfe/blockchain-libs/dist/secret/encryptors/aes256';
import {
  PartialTokenInfo,
  UnsignedTx,
} from '@onekeyfe/blockchain-libs/dist/types/provider';
import { IJsonRpcRequest } from '@onekeyfe/cross-inpage-provider-types';
import BigNumber from 'bignumber.js';
import { Conflux as ConfluxJs, Drip, JSBI } from 'js-conflux-sdk';
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

import { KeyringHardware } from './KeyringHardware';
import { KeyringHd } from './KeyringHd';
import { KeyringImported } from './KeyringImported';
import { KeyringWatching } from './KeyringWatching';

import type {
  Address,
  Transaction as TransactionClassType,
} from 'js-conflux-sdk';
import { TransactionOptions } from '@onekeyfe/js-sdk';

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

export interface IConfluxTransactionOption {
  from: Address;
  nonce?: JSBI;
  gasPrice?: JSBI;
  gas?: JSBI;
  to?: Address | null;
  value?: JSBI;
  storageLimit?: JSBI;
  epochHeight?: number;
  chainId?: number;
  data?: Buffer | string;
  r?: Buffer | string;
  s?: Buffer | string;
  v?: number;
}

const { decodeRaw } = Transaction as {
  decodeRaw: (hexString: string) => IConfluxTransactionOption;
};

const ConfluxTransaction: TransactionClassType = Transaction;

export default class Vault extends VaultBase {
  private conflux = new ConfluxJs({
    // should replace to dynamic address
    url: 'https://portal-test.confluxrpc.com',
    networkId: 1,
  });

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

  async decodeTx(encodedTx: IEncodedTxAny, payload?: any): Promise<any> {
    const transactionInfo = decodeRaw(encodedTx);
    return Promise.resolve({
      ...transactionInfo,
      fromAddress: transactionInfo.from,
      toAddress: transactionInfo.to,
      network: await this.getNetwork(),
    });
  }

  async getGasLimit(estimateTractionOptions: TransactionOptions) {
    const gasAndCollateral = await this.conflux.estimateGasAndCollateral(
      new ConfluxTransaction(estimateTractionOptions),
    );
    return gasAndCollateral.gasLimit[0];
  }

  async buildEncodedTxFromTransfer(
    transferInfo: ITransferInfo,
  ): Promise<string> {
    const dbAccount = (await this.getDbAccount()) as DBVariantAccount;
    const conflux = this.conflux
    const transaction = new ConfluxTransaction({
      to: transferInfo.to, // receiver address
      nonce: await conflux.getNextNonce(dbAccount.addresses[this.networkId]),
      value: transferInfo.amount,
      // 临时写死 gas
      gas: 21000,
      epochHeight: await conflux.getEpochNumber(),
      storageLimit: 0,
      chainId: 1,
      data: '0x',
      gasPrice: 1000000000,
    });

    // 没有 PRIVATE_KEY，conflux 的 transaction 不能执行 serialize，临时写死一个。
    const PRIVATE_KEY =
      '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
    transaction.sign(PRIVATE_KEY, 1);
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
  ): Promise<string> {
    // const network = await this.getNetwork();
    // const dbAccount = await this.getDbAccount();
    debugLogger.sendTx(
      'buildUnsignedTxFromEncodedTx >>>> buildUnsignedTx',
      encodedTx,
    );
    return Promise.resolve(encodedTx);
  }

  async fetchFeeInfo(encodedTx: any): Promise<IFeeInfo> {
    const feeInfo = decodeRaw(encodedTx);
    const network = await this.getNetwork();
    // TODO: should replace by constant variable
    const price: [number, boolean] = (await this.conflux.getGasPrice()) as any;
    return Promise.resolve({
      editable: false,
      nativeSymbol: network.symbol,
      nativeDecimals: network.decimals,
      symbol: network.feeSymbol,
      decimals: network.feeDecimals,
      limit: '2100',
      prices: [String(price[0] || 0)],
      tx: null, // Must be null if network not support feeInTx
    });
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
    return this.signAndSendTransaction(unsignedTx, options);
  }

  async signAndSendTransaction(
    unsignedTx: string,
    options: { password: string },
  ): Promise<string> {
    const signedTx = await this.signTransaction(unsignedTx, options);
    return await this.conflux.sendRawTransaction(signedTx);;
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
