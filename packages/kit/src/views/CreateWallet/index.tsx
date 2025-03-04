import React, { FC } from 'react';

import { useNavigation } from '@react-navigation/native';
import { useIntl } from 'react-intl';

import {
  Badge,
  HStack,
  Icon,
  Image,
  Modal,
  Typography,
  VStack,
} from '@onekeyhq/components';
import PressableItem from '@onekeyhq/components/src/Pressable/PressableItem';
import {
  CreateWalletModalRoutes,
  CreateWalletRoutesParams,
} from '@onekeyhq/kit/src/routes/Modal/CreateWallet';
import platformEnv from '@onekeyhq/shared/src/platformEnv';

import img1 from '../../../assets/app_wallet_icon.png';
import img2 from '../../../assets/hardware_icon.png';
import { ModalScreenProps, RootRoutesParams } from '../../routes/types';

type NavigationProps = ModalScreenProps<RootRoutesParams> &
  ModalScreenProps<CreateWalletRoutesParams>;

const CreateWalletModal: FC = () => {
  const intl = useIntl();
  const navigation = useNavigation<NavigationProps['navigation']>();

  const content = (
    <VStack space={8} w="full">
      <VStack space={4}>
        {/* APP Wallet option */}
        <PressableItem
          borderRadius="12px"
          px={4}
          onPress={() => {
            navigation.navigate(CreateWalletModalRoutes.NewWalletModal);
          }}
        >
          <HStack justifyContent="space-between" alignItems="center">
            <Image source={img1} width="10" height="12" alt="icon" />
            <Icon name="ChevronRightOutline" size={24} />
          </HStack>
          <VStack space={1} mt={6}>
            <Typography.Body1Strong>
              {intl.formatMessage({
                id: 'wallet__app_wallet',
              })}
            </Typography.Body1Strong>

            <Typography.Body2 color="text-subdued">
              {intl.formatMessage({
                id: 'content__app_wallet_desc',
              })}
            </Typography.Body2>
          </VStack>

          <Typography.Caption mt={4} color="text-disabled">
            {intl.formatMessage({
              id: 'content__for_people_who_dont_have_hardware_wallet',
            })}
          </Typography.Caption>
        </PressableItem>

        {/* Hardware Wallet option */}
        <PressableItem
          borderRadius="12px"
          px={4}
          onPress={() => {
            if (platformEnv.isExtension) return;
            navigation.navigate(CreateWalletModalRoutes.ConnectHardwareModal);
          }}
        >
          <HStack justifyContent="space-between" alignItems="center">
            <Image source={img2} width="10" height="12" alt="icon" />
            {platformEnv.isExtension ? (
              <Badge
                title={intl.formatMessage({ id: 'badge__coming_soon' })}
                size="sm"
                type="default"
              />
            ) : (
              <Icon name="ChevronRightOutline" size={24} />
            )}
          </HStack>
          <VStack space={1} mt={6}>
            <Typography.Body1Strong>
              {intl.formatMessage({
                id: 'wallet__hardware_wallet',
              })}
            </Typography.Body1Strong>

            <Typography.Body2 color="text-subdued">
              {intl.formatMessage({
                id: 'content__hardware_wallet_desc',
              })}
            </Typography.Body2>
          </VStack>

          <Typography.Caption mt={4} color="text-disabled">
            {intl.formatMessage({
              id: 'content__for_people_who_have_hardware_wallet',
            })}
          </Typography.Caption>
        </PressableItem>
      </VStack>
    </VStack>
  );

  return (
    <Modal
      header={intl.formatMessage({ id: 'action__create_wallet' })}
      footer={null}
      scrollViewProps={{
        children: content,
      }}
    />
  );
};

export default CreateWalletModal;
