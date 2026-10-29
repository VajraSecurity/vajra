import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

vi.mock(import('@/api/services/authApi'), async (orig) => ({
  ...(await orig()),
  setupMfaSettings: vi.fn(),
  verifyMfaSettings: vi.fn(),
  logout: vi.fn(),
}));

import * as authApi from '@/api/services/authApi';
import { ConfirmDialogContext } from '@/context/useConfirm';
import { MfaSetupModal } from '@/features/Settings/mfa/MfaSetupModal';
import { PREDEFINED_QUESTIONS } from '@/features/Settings/mfa/constants';

const api = vi.mocked(authApi);
const confirm = vi.fn().mockResolvedValue(false);

function renderModal() {
  return render(
    <ConfirmDialogContext.Provider value={{ confirm }}>
      <MfaSetupModal isOpen onClose={vi.fn()} onSuccess={vi.fn()} />
    </ConfirmDialogContext.Provider>,
  );
}

// Scans past step 1 and answers the security questions on step 2.
async function reachLastStep(user: ReturnType<typeof userEvent.setup>) {
  await user.click(await screen.findByRole('button', { name: /I've scanned it/ }));
  await user.selectOptions(await screen.findByLabelText('Security question 1'), PREDEFINED_QUESTIONS[0]);
  await user.type(screen.getByLabelText('Answer 1'), 'rex');
  await user.selectOptions(screen.getByLabelText('Security question 2'), PREDEFINED_QUESTIONS[1]);
  await user.type(screen.getByLabelText('Answer 2'), 'springfield');
  await user.click(screen.getByRole('button', { name: 'Next' }));
  await user.click(await screen.findByRole('checkbox'));
}

beforeEach(() => {
  // input-otp probes for password-manager badges with elementFromPoint,
  // which jsdom doesn't implement.
  document.elementFromPoint = () => null;
  api.setupMfaSettings.mockResolvedValue({
    status: 'Success',
    qrCode: 'data:image/png;base64,AAAA',
    secret: 'JBSWY3DPEHPK3PXP',
    recoveryCodes: ['aaaa-bbbb', 'cccc-dddd'],
  } as Awaited<ReturnType<typeof authApi.setupMfaSettings>>);
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe('MfaSetupModal', () => {
  it('asks for the authenticator code only on the last step and sends it once', async () => {
    api.verifyMfaSettings.mockResolvedValue({ status: 'Success', message: 'ok' });
    const user = userEvent.setup();
    renderModal();

    await screen.findByRole('button', { name: /I've scanned it/ });
    expect(screen.queryByLabelText(/6-digit code/)).not.toBeInTheDocument();

    await reachLastStep(user);
    const finish = screen.getByRole('button', { name: 'Finish setup' });
    expect(finish).toBeDisabled();

    await user.type(screen.getByLabelText(/6-digit code/), '123456');
    await user.click(finish);

    await waitFor(() => expect(api.verifyMfaSettings).toHaveBeenCalledTimes(1));
    expect(api.verifyMfaSettings).toHaveBeenCalledWith(expect.objectContaining({
      token: '123456',
      securityQuestion1: PREDEFINED_QUESTIONS[0],
      securityAnswer1: 'rex',
    }));
    expect(await screen.findByText(/Two-factor authentication is on/)).toBeInTheDocument();
  });

  it('keeps the user on the last step when the code is rejected', async () => {
    api.verifyMfaSettings.mockResolvedValue({ status: 'Fail', message: 'Invalid MFA code' });
    const user = userEvent.setup();
    renderModal();

    await reachLastStep(user);
    await user.type(screen.getByLabelText(/6-digit code/), '000000');
    await user.click(screen.getByRole('button', { name: 'Finish setup' }));

    expect(await screen.findByText('Invalid MFA code. Enter the current code from your authenticator app.')).toBeInTheDocument();
    // Still on the last step: the recovery codes and the code entry are shown,
    // the security answers are kept, and a new code can be tried.
    expect(screen.getByRole('button', { name: 'Finish setup' })).toBeInTheDocument();
    expect(screen.getByLabelText(/6-digit code/)).toHaveValue('');

    api.verifyMfaSettings.mockResolvedValue({ status: 'Success', message: 'ok' });
    await user.type(screen.getByLabelText(/6-digit code/), '654321');
    await user.click(screen.getByRole('button', { name: 'Finish setup' }));
    await waitFor(() => expect(api.verifyMfaSettings).toHaveBeenLastCalledWith(expect.objectContaining({
      token: '654321',
      securityAnswer2: 'springfield',
    })));
  });
});
