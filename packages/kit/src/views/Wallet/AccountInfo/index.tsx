/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
import React, { FC, useCallback } from 'react';

import { useNavigation } from '@react-navigation/core';
import { useIntl } from 'react-intl';

import {
  Box,
  Button,
  Icon,
  IconButton,
  Pressable,
  Typography,
  useIsVerticalLayout,
  useToast,
} from '@onekeyhq/components';
import Skeleton from '@onekeyhq/components/src/Skeleton';
import { Text } from '@onekeyhq/components/src/Typography';
import { shortenAddress } from '@onekeyhq/components/src/utils';
import { copyToClipboard } from '@onekeyhq/components/src/utils/ClipboardUtils';
import {
  FormatBalance,
  FormatCurrency,
} from '@onekeyhq/kit/src/components/Format';
import { useActiveWalletAccount } from '@onekeyhq/kit/src/hooks/redux';
import { useManageTokens } from '@onekeyhq/kit/src/hooks/useManageTokens';
import { ReceiveTokenRoutes } from '@onekeyhq/kit/src/routes/Modal/routes';
import type { ReceiveTokenRoutesParams } from '@onekeyhq/kit/src/routes/Modal/types';
import {
  ModalRoutes,
  ModalScreenProps,
  RootRoutes,
} from '@onekeyhq/kit/src/routes/types';
import extUtils from '@onekeyhq/kit/src/utils/extUtils';
import platformEnv from '@onekeyhq/shared/src/platformEnv';

import { setHaptics } from '../../../hooks/setHaptics';
import { SendRoutes, SendRoutesParams } from '../../Send/types';

type NavigationProps = ModalScreenProps<ReceiveTokenRoutesParams> &
  ModalScreenProps<SendRoutesParams>;

export const FIXED_VERTICAL_HEADER_HEIGHT = 258;
export const FIXED_HORIZONTAL_HEDER_HEIGHT = 214;

type AccountAmountInfoProps = { isCenter: boolean };
const AccountAmountInfo: FC<AccountAmountInfoProps> = ({ isCenter }) => {
  const intl = useIntl();
  const toast = useToast();

  const { account, network: activeNetwork } = useActiveWalletAccount();
  const { prices, balances } = useManageTokens({
    pollingInterval: 15000,
  });

  const copyContentToClipboard = useCallback(
    (address) => {
      if (!address) return;
      copyToClipboard(address);
      toast.show({ title: intl.formatMessage({ id: 'msg__address_copied' }) });
    },
    [toast, intl],
  );

  return (
    <Box alignItems={isCenter ? 'center' : 'flex-start'}>
      <Typography.Subheading color="text-subdued">
        {intl.formatMessage({ id: 'asset__total_balance' }).toUpperCase()}
      </Typography.Subheading>
      <Box flexDirection="row" mt={2}>
        {balances.main ? (
          <FormatBalance
            balance={balances.main}
            suffix={activeNetwork?.symbol?.toUpperCase?.()}
            as={Typography.DisplayXLarge}
            formatOptions={{
              fixed: activeNetwork?.nativeDisplayDecimals ?? 6,
            }}
            render={(ele) => (
              <Typography.DisplayXLarge>{ele}</Typography.DisplayXLarge>
            )}
          />
        ) : (
          <Skeleton shape="DisplayXLarge" />
        )}
      </Box>
      {prices.main && balances.main ? (
        <FormatCurrency
          numbers={[
            prices?.main,
            balances.main,
            !balances.main ? undefined : 1,
          ]}
          render={(ele) => <Typography.Body2 mt={1}>{ele}</Typography.Body2>}
        />
      ) : (
        <Box mt={1}>
          <Skeleton shape="Body2" />
        </Box>
      )}
      <Pressable
        mt={4}
        onPress={() => {
          setHaptics();
          copyContentToClipboard(account?.address);
        }}
      >
        {({ isHovered, isPressed }) => (
          <Box
            py={{ base: 2, md: 1 }}
            px={{ base: 3, md: 2 }}
            rounded="xl"
            bg={
              // eslint-disable-next-line no-nested-ternary
              isPressed
                ? 'surface-neutral-pressed'
                : isHovered
                ? 'surface-neutral-default'
                : 'surface-neutral-subdued'
            }
            flexDirection="row"
          >
            <Text typography={{ sm: 'Body2', md: 'CaptionStrong' }} mr={2}>
              {shortenAddress(account?.address ?? '')}
            </Text>
            <Icon name="DuplicateSolid" size={isCenter ? 20 : 16} />
          </Box>
        )}
      </Pressable>
    </Box>
  );
};

type AccountOptionProps = { isSmallView: boolean };
const AccountOption: FC<AccountOptionProps> = ({ isSmallView }) => {
  const { getTokenBalance } = useManageTokens();
  const intl = useIntl();
  const navigation = useNavigation<NavigationProps['navigation']>();
  const { wallet, account } = useActiveWalletAccount();
  return (
    <Box flexDirection="row" justifyContent="center" alignItems="center">
      <Button
        size={isSmallView ? 'lg' : 'base'}
        leftIconName="ArrowUpSolid"
        minW={{ base: '126px', md: 'auto' }}
        type="basic"
        isDisabled={
          wallet?.type === 'watching' ||
          !account ||
          parseFloat(getTokenBalance()) <= 0
        }
        onPress={() => {
          navigation.navigate(RootRoutes.Modal, {
            screen: ModalRoutes.Send,
            params: {
              screen: SendRoutes.Send,
              params: {},
            },
          });
        }}
      >
        {intl.formatMessage({ id: 'action__send' })}
      </Button>
      <Button
        size={isSmallView ? 'lg' : 'base'}
        ml={4}
        leftIconName="ArrowDownSolid"
        minW={{ base: '126px', md: 'auto' }}
        type="basic"
        isDisabled={wallet?.type === 'watching' || !account}
        onPress={() => {
          if (!account) return;
          navigation.navigate(RootRoutes.Modal, {
            screen: ModalRoutes.Receive,
            params: {
              screen: ReceiveTokenRoutes.ReceiveToken,
              params: {
                address: account.address,
                name: account.name,
              },
            },
          });
        }}
      >
        {intl.formatMessage({ id: 'action__receive' })}
      </Button>
      {platformEnv.isExtensionUiPopup && platformEnv.isDev && (
        <IconButton
          onPress={() => {
            extUtils.openExpandTab({ routes: '' });
          }}
          ml={4}
          name="ArrowsExpandOutline"
        />
      )}
    </Box>
  );
};

const AccountInfo = () => {
  const isSmallView = useIsVerticalLayout();
  if (isSmallView) {
    return (
      <Box
        py={8}
        w="100%"
        px={4}
        flexDirection="column"
        bgColor="background-default"
        h={FIXED_VERTICAL_HEADER_HEIGHT}
      >
        <AccountAmountInfo isCenter={isSmallView} />
        <Box mt={8}>
          <AccountOption isSmallView={isSmallView} />
        </Box>
      </Box>
    );
  }
  return (
    <Box
      h={FIXED_HORIZONTAL_HEDER_HEIGHT}
      py={12}
      px={4}
      flexDirection="row"
      justifyContent="space-between"
      alignItems="center"
      bgColor="background-default"
    >
      <AccountAmountInfo isCenter={isSmallView} />
      <Box>
        <AccountOption isSmallView={isSmallView} />
      </Box>
    </Box>
  );
};

export default AccountInfo;
