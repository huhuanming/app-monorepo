import React, { FC, useEffect } from 'react';

import { useIntl } from 'react-intl';

import {
  Dialog,
  Form,
  useForm,
  useIsVerticalLayout,
  useToast,
} from '@onekeyhq/components';
import DialogCommon from '@onekeyhq/components/src/Dialog/components';
import { Account } from '@onekeyhq/engine/src/types/account';

import backgroundApiProxy from '../../../background/instance/backgroundApiProxy';

type FieldValues = { name: string };

export type AccountModifyNameDialogProps = {
  visible: boolean;
  account: Account | undefined;
  onDone: (account: Account) => void;
  onClose: () => void;
};

const AccountModifyNameDialog: FC<AccountModifyNameDialogProps> = ({
  visible,
  account,
  onDone,
  onClose,
}) => {
  const intl = useIntl();
  const toast = useToast();
  const { serviceAccount } = backgroundApiProxy;

  const [isLoading, setIsLoading] = React.useState(false);
  const isSmallScreen = useIsVerticalLayout();

  const { control, handleSubmit, setError, reset } = useForm<FieldValues>({
    defaultValues: { name: '' },
  });

  useEffect(() => {
    if (!visible) {
      reset();
    }
  }, [visible, reset]);

  const onSubmit = handleSubmit(async (values: FieldValues) => {
    if (!account) return;

    setIsLoading(true);
    const changedAccount = await serviceAccount.setAccountName(
      account.id,
      values.name,
    );

    if (changedAccount) {
      toast.show({ title: intl.formatMessage({ id: 'msg__renamed' }) });
      onClose();
      onDone(account);
    } else {
      setError('name', {
        message: intl.formatMessage({ id: 'msg__unknown_error' }),
      });
    }
    setIsLoading(false);
  });

  return (
    <>
      {visible && (
        <Dialog visible={visible} hasFormInsideDialog>
          <Form>
            <Form.Item
              name="name"
              defaultValue=""
              control={control}
              rules={{
                required: intl.formatMessage({ id: 'form__field_is_required' }),
                maxLength: {
                  value: 24,
                  message: intl.formatMessage(
                    {
                      id: 'form__account_name_invalid_characters_limit',
                    },
                    { 0: '24' },
                  ),
                },
              }}
            >
              <Form.Input
                size={isSmallScreen ? 'xl' : 'default'}
                autoFocus
                focusable
                placeholder={account?.name ?? ''}
              />
            </Form.Item>
            <DialogCommon.FooterButton
              marginTop={0}
              secondaryActionTranslationId="action__cancel"
              onSecondaryActionPress={() => onClose()}
              onPrimaryActionPress={() => onSubmit()}
              primaryActionTranslationId="action__rename"
              primaryActionProps={{
                isLoading,
              }}
            />
          </Form>
        </Dialog>
      )}
    </>
  );
};

export default AccountModifyNameDialog;
