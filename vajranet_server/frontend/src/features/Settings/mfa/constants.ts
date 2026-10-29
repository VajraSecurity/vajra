export const PREDEFINED_QUESTIONS = [
  "What is your mother's maiden name?",
  "What was the name of your first pet?",
  "What was the model of your first car?",
  "In what city were you born?",
  "What is your favorite childhood teacher's name?",
  "What was your childhood nickname?",
] as const;

export const MFA_STEPS = [
  { id: 1, title: "Authenticator", description: "Scan the QR code" },
  { id: 2, title: "Backup Questions", description: "Security questions" },
  { id: 3, title: "Recovery Codes", description: "Save codes & verify" },
] as const;
