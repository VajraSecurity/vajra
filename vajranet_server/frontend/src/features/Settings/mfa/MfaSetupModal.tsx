import { useEffect, useRef, useState } from "react";
import { motion, AnimatePresence, MotionConfig, useAnimation } from "motion/react";
import { REGEXP_ONLY_DIGITS } from "input-otp";
import { CheckCircle2, XCircle, ShieldCheck } from "lucide-react";
import { logout, setupMfaSettings, verifyMfaSettings } from "@/api/api";
import { clearAuthData } from "@/services/auth";
import { sanitizeAsciiSingleLine } from "@/services/inputSanitizers";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { InputOTP, InputOTPGroup, InputOTPSlot } from "@/components/ui/input-otp";
import { useConfirm } from "@/context/useConfirm";
import { MfaStepper } from "./MfaStepper";
import { AuthMethodCard } from "./AuthMethodCard";
import { QrSetupCard } from "./QrSetupCard";
import { SecurityQuestionsStep } from "./SecurityQuestionsStep";
import { RecoveryCodesCard } from "./RecoveryCodesCard";
import { DuoSpinner } from "@/components/ui/loading";

interface MfaSetupModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
}

interface StatusMessage {
  type: "success" | "error";
  text: string;
}

function StatusBanner({ message }: { message: StatusMessage }) {
  const isSuccess = message.type === "success";
  return (
    <motion.div
      initial={{ opacity: 0, y: -6, height: 0 }}
      animate={{ opacity: 1, y: 0, height: "auto" }}
      exit={{ opacity: 0, height: 0 }}
      transition={{ duration: 0.18 }}
      role="status"
      aria-live="polite"
      className={`mb-4 flex items-start gap-2 overflow-hidden rounded-xl p-3 text-sm font-medium ${isSuccess
          ? "bg-emerald-50 text-emerald-700 dark:bg-emerald-950/30 dark:text-emerald-400"
          : "bg-red-50 text-red-700 dark:bg-red-950/30 dark:text-red-400"
        }`}
    >
      {isSuccess ? (
        <CheckCircle2 className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
      ) : (
        <XCircle className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
      )}
      <span>{message.text}</span>
    </motion.div>
  );
}

const PRIMARY_BUTTON_CLASS = "metallic-btn-blue flex-1 border-transparent";
const OUTLINE_BUTTON_CLASS = "flex-1 border-gray-300 text-gray-700 hover:bg-gray-50 hover:text-gray-900";

const stepVariants = {
  enter: (dir: number) => ({ opacity: 0, x: dir > 0 ? 16 : -16 }),
  center: { opacity: 1, x: 0 },
  exit: (dir: number) => ({ opacity: 0, x: dir > 0 ? -16 : 16 }),
};

export function MfaSetupModal({ isOpen, onClose, onSuccess }: MfaSetupModalProps) {
  const confirm = useConfirm();
  const [loading, setLoading] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [message, setMessage] = useState<StatusMessage | null>(null);

  const [qrCode, setQrCode] = useState("");
  const [secret, setSecret] = useState<string | undefined>(undefined);
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);
  const [generatedAt, setGeneratedAt] = useState<Date | null>(null);

  const [mfaCode, setMfaCode] = useState("");
  const [otpError, setOtpError] = useState(false);
  const otpControls = useAnimation();

  const [step, setStep] = useState(1);
  const [direction, setDirection] = useState(1);
  const [securityQuestion1, setSecurityQuestion1] = useState("");
  const [securityAnswer1, setSecurityAnswer1] = useState("");
  const [securityQuestion2, setSecurityQuestion2] = useState("");
  const [securityAnswer2, setSecurityAnswer2] = useState("");
  const [codesSaved, setCodesSaved] = useState(false);

  const finishingRef = useRef(false);
  const step1Ref = useRef<HTMLFormElement>(null);
  const step2Ref = useRef<HTMLFormElement>(null);
  const step3Ref = useRef<HTMLFormElement>(null);

  const focusStepOnEnter = (definition: unknown, ref: React.RefObject<HTMLElement | null>) => {
    if (definition === "center") {
      ref.current?.focus();
    }
  };

  useEffect(() => {
    if (isOpen) {
      setLoading(true);
      setupMfaSettings()
        .then((res) => {
          if (res.status === "Success") {
            setQrCode(res.qrCode || "");
            setSecret(res.secret);
            setRecoveryCodes(res.recoveryCodes || []);
            setGeneratedAt(new Date());
          } else {
            setMessage({ type: "error", text: res.message || "Failed to set up MFA" });
          }
        })
        .catch((err) => setMessage({ type: "error", text: err.message || "Failed to set up MFA" }))
        .finally(() => setLoading(false));
    } else {
      setQrCode("");
      setSecret(undefined);
      setRecoveryCodes([]);
      setGeneratedAt(null);
      setMfaCode("");
      setOtpError(false);
      setStep(1);
      setDirection(1);
      setSecurityQuestion1("");
      setSecurityAnswer1("");
      setSecurityQuestion2("");
      setSecurityAnswer2("");
      setCodesSaved(false);
      setMessage(null);
      finishingRef.current = false;
    }
  }, [isOpen]);

  const goToStep = (next: number) => {
    setDirection(next > step ? 1 : -1);
    setMessage(null);
    setStep(next);
  };

  // Once past the QR step (step > 1), the app is already linked on the
  // user's phone. Closing the modal at that point
  // should never happen silently, so any explicit close attempt (the header
  // "X" or a Cancel button) is gated behind a confirmation instead of
  // closing right away.
  const handleRequestClose = async () => {
    if (step > 1) {
      const shouldClose = await confirm({
        title: "Cancel two-factor authentication setup?",
        description:
          "Your authenticator app is already linked, but setup isn't finished yet. If you cancel now you'll need to start over.",
        confirmLabel: "Cancel setup",
        cancelLabel: "Keep going",
        variant: "danger",
      });
      if (!shouldClose) return;
    }
    onClose();
  };

  const handleDownload = () => {
    const text = `VajraNet Emergency Recovery Codes\n\n${recoveryCodes.join(
      "\n"
    )}\n\nKeep these safe. They are the only way to access your account if you lose your authenticator device.`;
    const blob = new Blob([text], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "vajranet-recovery-codes.txt";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const rejectCode = (reason: string) => {
    const sentence = reason.trim().replace(/[.!]?$/, ".");
    setMfaCode("");
    setOtpError(true);
    setMessage({ type: "error", text: `${sentence} Enter the current code from your authenticator app.` });
    otpControls.start({ x: [0, -8, 8, -6, 6, 0], transition: { duration: 0.4 } });
  };

  // The authenticator code is asked for here, on the last step, and checked
  // once by verify-setup, which also turns MFA on. Asking for it on the
  // first step instead meant the code had expired (or, being single-use,
  // had already been spent on a preview check) by the time setup finished.
  const handleFinish = async () => {
    if (finishingRef.current || mfaCode.length !== 6) return;
    finishingRef.current = true;
    setSubmitting(true);
    setMessage(null);
    setOtpError(false);
    try {
      const response = await verifyMfaSettings({
        token: mfaCode,
        securityQuestion1,
        securityAnswer1,
        securityQuestion2,
        securityAnswer2,
      });
      if (response.status === "Success" || response.status === "success") {
        setMessage({ type: "success", text: "Two-factor authentication is on. You'll be logged out to re-authenticate." });
        setTimeout(async () => {
          onSuccess();
          onClose();
          try {
            await logout();
          } catch {
            // ignore — we're forcing a re-auth regardless
          }
          clearAuthData();
          window.location.href = "/login";
        }, 1800);
      } else {
        rejectCode(response.message || "That code didn't work");
        finishingRef.current = false;
      }
    } catch (error) {
      const errMessage = error instanceof Error ? error.message : "";
      rejectCode(errMessage || "That code didn't work");
      finishingRef.current = false;
    } finally {
      setSubmitting(false);
    }
  };

  const isStep2Valid =
    !!securityQuestion1 &&
    !!securityAnswer1.trim() &&
    !!securityQuestion2 &&
    !!securityAnswer2.trim() &&
    securityQuestion1 !== securityQuestion2;

  // Explains why the Next button below is disabled, so the user isn't left
  // guessing what's missing.
  const step2Hint = (() => {
    if (
      !securityQuestion1 ||
      !securityAnswer1.trim() ||
      !securityQuestion2 ||
      !securityAnswer2.trim()
    ) {
      return "Answer both security questions to continue.";
    }
    if (securityQuestion1 === securityQuestion2) {
      return "Choose two different questions.";
    }
    return null;
  })();

  return (
    <Dialog
      open={isOpen}
      onOpenChange={(open, eventDetails) => {
        if (open) return;
        if (eventDetails.reason === "close-press") {
          // Explicit close via the header "X" — always route through the
          // confirmation gate (a no-op once step === 1).
          eventDetails.cancel();
          handleRequestClose();
          return;
        }
        if (step > 1) {
          // Outside clicks / Escape / focus-out must never silently discard
          // an in-progress, already-linked setup.
          eventDetails.cancel();
          return;
        }
        onClose();
      }}
    >
      <DialogContent className="max-w-lg" showCloseButton>
        <MotionConfig reducedMotion="user">
          <DialogHeader>
            <div className="flex items-center gap-2.5">
              <div className="flex size-9 shrink-0 items-center justify-center rounded-xl bg-blue-100 text-blue-600">
                <ShieldCheck className="size-5" aria-hidden="true" />
              </div>
              <div>
                <DialogTitle>Set up two-factor authentication</DialogTitle>
                <DialogDescription>Add a second step to keep your account safe.</DialogDescription>
              </div>
            </div>
          </DialogHeader>

          <div className="px-6 pb-6 pt-5">
            <div className="mb-5">
              <MfaStepper currentStep={step} />
            </div>

            <AnimatePresence mode="wait" initial={false}>
              {message && <StatusBanner key={message.text} message={message} />}
            </AnimatePresence>

            {loading ? (
              <div className="flex flex-col items-center justify-center gap-3 py-14 text-gray-500">
                <DuoSpinner size="lg" className="text-blue-600" />
                <p className="text-sm">Preparing your setup…</p>
              </div>
            ) : (
              <AnimatePresence mode="wait" custom={direction} initial={false}>
                {step === 1 && (
                  <motion.form
                    key="step-1"
                    ref={step1Ref}
                    tabIndex={-1}
                    custom={direction}
                    variants={stepVariants}
                    initial="enter"
                    animate="center"
                    exit="exit"
                    transition={{ duration: 0.2, ease: "easeOut" }}
                    onAnimationComplete={(definition) => focusStepOnEnter(definition, step1Ref)}
                    onSubmit={(e) => {
                      e.preventDefault();
                      goToStep(2);
                    }}
                    className="space-y-4 outline-none"
                  >
                    <AuthMethodCard />
                    <QrSetupCard qrCode={qrCode} secret={secret} />

                    <div className="flex gap-3 pt-1">
                      <Button type="button" variant="outline" onClick={handleRequestClose} className={OUTLINE_BUTTON_CLASS}>
                        Cancel
                      </Button>
                      <Button type="submit" disabled={!qrCode} className={PRIMARY_BUTTON_CLASS}>
                        I&apos;ve scanned it
                      </Button>
                    </div>
                  </motion.form>
                )}

                {step === 2 && (
                  <motion.form
                    key="step-2"
                    ref={step2Ref}
                    tabIndex={-1}
                    custom={direction}
                    variants={stepVariants}
                    initial="enter"
                    animate="center"
                    exit="exit"
                    transition={{ duration: 0.2, ease: "easeOut" }}
                    onAnimationComplete={(definition) => focusStepOnEnter(definition, step2Ref)}
                    onSubmit={(e) => {
                      e.preventDefault();
                      goToStep(3);
                    }}
                    className="space-y-4 outline-none"
                  >
                    <SecurityQuestionsStep
                      question1={securityQuestion1}
                      answer1={securityAnswer1}
                      question2={securityQuestion2}
                      answer2={securityAnswer2}
                      onQuestion1Change={setSecurityQuestion1}
                      onAnswer1Change={(v) => setSecurityAnswer1(sanitizeAsciiSingleLine(v, 128, false))}
                      onQuestion2Change={setSecurityQuestion2}
                      onAnswer2Change={(v) => setSecurityAnswer2(sanitizeAsciiSingleLine(v, 128, false))}
                    />
                    {step2Hint && (
                      <p className="text-xs text-gray-500" role="status">
                        {step2Hint}
                      </p>
                    )}
                    <div className="flex gap-3 pt-1">
                      <Button type="button" variant="outline" onClick={() => goToStep(1)} className={OUTLINE_BUTTON_CLASS}>
                        Back
                      </Button>
                      <Button type="submit" disabled={!isStep2Valid} className={PRIMARY_BUTTON_CLASS}>
                        Next
                      </Button>
                    </div>
                  </motion.form>
                )}

                {step === 3 && (
                  <motion.form
                    key="step-3"
                    ref={step3Ref}
                    tabIndex={-1}
                    custom={direction}
                    variants={stepVariants}
                    initial="enter"
                    animate="center"
                    exit="exit"
                    transition={{ duration: 0.2, ease: "easeOut" }}
                    onAnimationComplete={(definition) => focusStepOnEnter(definition, step3Ref)}
                    onSubmit={(e) => {
                      e.preventDefault();
                      if (codesSaved) handleFinish();
                    }}
                    className="space-y-4 outline-none"
                  >
                    <RecoveryCodesCard codes={recoveryCodes} generatedAt={generatedAt} onDownload={handleDownload} />

                    <label className="flex cursor-pointer items-start gap-2.5 rounded-xl border border-border p-3 transition-colors hover:bg-muted/40">
                      <input
                        type="checkbox"
                        checked={codesSaved}
                        onChange={(e) => setCodesSaved(e.target.checked)}
                        className="mt-0.5 size-4 shrink-0 rounded border-input accent-primary"
                      />
                      <span className="text-sm text-foreground">
                        I&apos;ve saved my recovery codes somewhere safe and understand each one only works once.
                      </span>
                    </label>

                    <div>
                      <label htmlFor="mfa-otp-input" className="mb-2 block text-center text-sm font-medium text-foreground">
                        Enter the 6-digit code from your authenticator app
                      </label>
                      <motion.div animate={otpControls} className="flex justify-center">
                        <InputOTP
                          id="mfa-otp-input"
                          maxLength={6}
                          value={mfaCode}
                          onChange={setMfaCode}
                          pattern={REGEXP_ONLY_DIGITS}
                        >
                          <InputOTPGroup>
                            {Array.from({ length: 6 }).map((_, i) => (
                              <InputOTPSlot
                                key={i}
                                index={i}
                                total={6}
                                invalid={otpError}
                              />
                            ))}
                          </InputOTPGroup>
                        </InputOTP>
                      </motion.div>
                      {otpError && (
                        <p id="mfa-otp-error" className="sr-only">
                          Invalid code, please try again
                        </p>
                      )}
                    </div>

                    <div className="flex gap-3 pt-1">
                      <Button type="button" variant="outline" onClick={() => goToStep(2)} className="flex-1">
                        Back
                      </Button>
                      <Button type="submit" disabled={!codesSaved || mfaCode.length !== 6 || submitting} className="flex-1">
                        {submitting ? (
                          <>
                            <DuoSpinner size="sm" />
                            Finishing…
                          </>
                        ) : (
                          "Finish setup"
                        )}
                      </Button>
                    </div>
                  </motion.form>
                )}
              </AnimatePresence>
            )}
          </div>
        </MotionConfig>
      </DialogContent>
    </Dialog>
  );
}

export default MfaSetupModal;
