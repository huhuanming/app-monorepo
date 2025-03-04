import React, { FC } from 'react';

import { useIntl } from 'react-intl';

import { Dialog, useToast } from '@onekeyhq/components';
import { OnCloseCallback } from '@onekeyhq/components/src/Dialog/components/FooterButton';

import backgroundApiProxy from '../../../background/instance/backgroundApiProxy';
import { useActiveWalletAccount } from '../../../hooks/redux';
import { setRefreshTS } from '../../../store/reducers/settings';

export type DeleteWalletProp = {
  walletId: string;
  password: string;
};

type ManagerWalletDeleteDialogProps = {
  visible: boolean;
  deleteWallet: DeleteWalletProp | undefined;
  onDialogClose: () => void;
};

const ManagerWalletDeleteDialog: FC<ManagerWalletDeleteDialogProps> = ({
  visible,
  deleteWallet,
  onDialogClose,
}) => {
  const intl = useIntl();
  const toast = useToast();
  const { wallet: activeWallet } = useActiveWalletAccount();
  const { dispatch, engine, serviceAccount } = backgroundApiProxy;

  const { walletId, password } = deleteWallet ?? {};
  const [isLoading, setIsLoading] = React.useState(false);

  return (
    <Dialog
      visible={visible}
      canceledOnTouchOutside={false}
      onClose={() => onDialogClose?.()}
      contentProps={{
        iconType: 'danger',
        title: intl.formatMessage({
          id: 'action__delete_wallet',
        }),
        content: intl.formatMessage({
          id: 'dialog__delete_wallet_desc',
        }),
      }}
      footerButtonProps={{
        primaryActionProps: {
          type: 'destructive',
          children: intl.formatMessage({ id: 'action__delete' }),
          isLoading,
        },
        onPrimaryActionPress: ({ onClose }: OnCloseCallback) => {
          if (!walletId) return;

          setIsLoading(true);

          engine
            .getWallet(walletId)
            .then(async (wallet) => {
              await engine.removeWallet(walletId, password ?? '');
              if (activeWallet?.id === walletId) {
                await serviceAccount.autoChangeWallet();
              }
              dispatch(setRefreshTS());
              toast.show({
                title: intl.formatMessage(
                  { id: 'msg__wallet_deleted' },
                  { 0: wallet.name },
                ),
              });
              onClose?.();
            })
            .catch((e) => {
              toast.show({
                title: intl.formatMessage({ id: 'msg__unknown_error' }),
              });
              console.log(e);
            })
            .finally(() => {
              setIsLoading(false);
            });
        },
      }}
    />
  );
};

export default ManagerWalletDeleteDialog;
