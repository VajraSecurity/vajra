import { useState } from "react";
import { useNavigate } from "react-router-dom";
import {
    EyeIcon,
    EyeSlashIcon,
    EnvelopeIcon,
    LockClosedIcon,
    ShieldCheckIcon,
    ComputerDesktopIcon,
    BuildingOffice2Icon,
} from "@heroicons/react/24/outline";
import { getProfile, login, verifyMfa, recoverMfa } from '../../api/api';
import { sanitizeUserForCache } from '../../services/auth';
import { sanitizeAsciiSingleLine } from '../../services/inputSanitizers';
import vajraLogo from "../../assets/vajra/vajralogo-white.png";
import { HexagonBackground } from "../../components/animate-ui/components/backgrounds/hexagon";
import SideRays from "../../components/SideRays/SideRays";

const NAVY = "#1e3a8a";
const NAVY_DARK = "#172d6e";
const CARD_BG = "#1a3070";

const FEATURES = [
    {
        num: 1,
        Icon: ShieldCheckIcon,
        title: "Real-time Threat Detection",
        desc: "Instant endpoint monitoring across all your devices",
    },
    {
        num: 2,
        Icon: ComputerDesktopIcon,
        title: "24/7 Monitoring",
        desc: "Continuous threat detection and response",
    },
    {
        num: 3,
        Icon: BuildingOffice2Icon,
        title: "Enterprise Security",
        desc: "Hardened controls for modern security teams",
    },
];

export default function LoginForm() {
    const [showPassword, setShowPassword] = useState(false);
    const [email, setEmail] = useState("");
    const [password, setPassword] = useState("");
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState("");
    const [success, setSuccess] = useState("");

    const [captchaRequired, setCaptchaRequired] = useState(false);
    const [captchaImg, setCaptchaImg] = useState<string | null | undefined>(null);
    const [captchaId, setCaptchaId] = useState<string | null | undefined>(null);
    const [captchaInput, setCaptchaInput] = useState("");

    const [mfaRequired, setMfaRequired] = useState(false);
    const [mfaToken, setMfaToken] = useState("");
    const [mfaCode, setMfaCode] = useState("");
    const [useRecoveryCode, setUseRecoveryCode] = useState(false);
    const [recoveryInput, setRecoveryInput] = useState("");


    const navigate = useNavigate();

    const handleLogin = async (e: { preventDefault: () => void }) => {
        e.preventDefault();
        setError("");
        setSuccess("");
        setLoading(true);

        try {
            const data = await login({
                email,
                password,
                ...(captchaRequired && {
                    captcha: captchaInput,
                    captchaId: captchaId ?? undefined,
                }),
            });

            if (data.status === "Success") {
                try {
                    const profile = await getProfile();
                    if (profile?.data) localStorage.setItem("user", JSON.stringify(sanitizeUserForCache(profile.data)));
                } catch {
                    // non-fatal
                }

                window.dispatchEvent(new Event('auth-change'));
                setSuccess(data.message || "Login successful! Redirecting...");
                setCaptchaRequired(false);
                setCaptchaImg(null);
                setCaptchaId(null);
                setCaptchaInput("");
                setTimeout(() => navigate("/my-devices"), 1500);
            } else if (data.status === "MfaRequired") {
                setMfaRequired(true);
                setMfaToken(data.mfaToken!);

            }
            else if (data.status === "CaptchaRequired") {
                setCaptchaRequired(true);
                setCaptchaImg(data.captcha ?? null);
                setCaptchaId(data.captchaId ?? null);
                setError(data.message || "Please complete CAPTCHA to continue.");
                setCaptchaInput("");

            } else if (data.status === "Fail") {
                setError(data.message || "Invalid email or password.");

            } else {
                setError("Unexpected error. Please try again.");
            }

        } catch (err) {
            setError(err instanceof Error ? err.message : "Login failed. Please try again.");
        } finally {
            setLoading(false);
        }
    };

    const handleMfaVerify = async (e: { preventDefault: () => void }) => {
        e.preventDefault();
        setError("");
        setSuccess("");
        setLoading(true);

        try {
            const data = await verifyMfa(mfaToken, mfaCode);

            if (data.status === "Success") {
                try {
                    const profile = await getProfile();
                    if (profile?.data) localStorage.setItem("user", JSON.stringify(sanitizeUserForCache(profile.data)));
                } catch { /* no-op */ }

                window.dispatchEvent(new Event('auth-change'));
                setSuccess(data.message || "Login successful! Redirecting...");
                setTimeout(() => navigate("/my-devices"), 1500);
            } else {
                setError(data.message || "Invalid MFA code.");
            }
        } catch (err) {
            setError(err instanceof Error ? err.message : "MFA verification failed.");
        } finally {
            setLoading(false);
        }
    };

    const handleMfaRecover = async (e: { preventDefault: () => void }) => {
        e.preventDefault();
        setError("");
        setSuccess("");
        setLoading(true);

        try {
            const data = await recoverMfa(mfaToken, recoveryInput);

            if (data.status === "Success") {
                try {
                    const profile = await getProfile();
                    if (profile?.data) localStorage.setItem("user", JSON.stringify(sanitizeUserForCache(profile.data)));
                } catch { /* no-op */ }

                window.dispatchEvent(new Event('auth-change'));
                setSuccess(data.message || "Login successful! Redirecting...");
                setTimeout(() => navigate("/my-devices"), 1500);
            } else {
                setError(data.message || "Invalid recovery code.");
            }
        } catch (err) {
            setError(err instanceof Error ? err.message : "Recovery failed.");
        } finally {
            setLoading(false);
        }
    };

    return (
        /* Page background */
        <HexagonBackground
            className="!bg-transparent min-h-screen flex items-center justify-center p-8"
            style={{ background: "linear-gradient(135deg, #e8edf5 0%, #f0f3f8 50%, #e4e9f2 100%)" }}
            hexagonProps={{}}
            hexagonSize={70}
            hexagonMargin={2}
        >
            {/* Floating card */}
            <div style={{
                position: "relative",
                zIndex: 10,
                display: "flex",
                width: "100%",
                maxWidth: 960,
                minHeight: 560,
                borderRadius: 20,
                overflow: "hidden",
                boxShadow: "0 20px 60px rgba(0,0,0,0.15)",
            }}>

                {/* LEFT PANEL */}
                <div className="hidden md:flex" style={{
                    position: "relative",
                    width: "50%",
                    background: NAVY,
                    flexDirection: "column",
                    alignItems: "center",
                    justifyContent: "center",
                    padding: "48px 40px",
                    boxSizing: "border-box",
                    textAlign: "center",
                    overflow: "hidden",
                }}>
                    {/* Animated ray effect */}
                    <SideRays />

                    {/* Content sits above the rays */}
                    <div style={{ position: "relative", zIndex: 1, width: "100%" }}>

                        {/* Logo */}
                        <div style={{ marginBottom: 32, display: "flex", justifyContent: "center", width: "100%" }}>
                            <img
                                src={vajraLogo}
                                alt="Vajra"
                                style={{ height: 36 }}
                            />
                        </div>

                        {/* Heading */}
                        <h1 style={{
                            color: "#ffffff",
                            fontSize: "clamp(22px, 2.2vw, 30px)",
                            fontWeight: 800,
                            lineHeight: 1.2,
                            marginBottom: 12,
                        }}>
                            Welcome back to Vajra.
                        </h1>

                        <p style={{
                            color: "rgba(255,255,255,0.9)",
                            fontSize: 14,
                            lineHeight: 1.7,
                            marginBottom: 36,
                            fontWeight: 600,
                        }}>
                            Instant endpoint detection &amp; response<br />for modern security teams.
                        </p>

                        {/* Feature cards */}
                        <div style={{ display: "flex", flexDirection: "column", gap: 12, width: "100%" }}>
                            {FEATURES.map((f) => (
                                <div key={f.num} style={{
                                    background: CARD_BG,
                                    borderRadius: 12,
                                    padding: "14px 18px",
                                    display: "flex",
                                    alignItems: "center",
                                    gap: 14,
                                    border: "1px solid rgba(255,255,255,0.08)",
                                    textAlign: "left",
                                }}>
                                    {/* Number badge */}
                                    <div style={{
                                        width: 34,
                                        height: 34,
                                        borderRadius: "50%",
                                        border: "2px solid rgba(255,255,255,0.3)",
                                        display: "flex",
                                        alignItems: "center",
                                        justifyContent: "center",
                                        flexShrink: 0,
                                        color: "#ffffff",
                                        fontSize: 13,
                                        fontWeight: 700,
                                    }}>
                                        {f.num}
                                    </div>

                                    {/* Icon */}
                                    <f.Icon style={{ width: 20, height: 20, color: "rgba(255,255,255,0.65)", flexShrink: 0 }} />

                                    {/* Text */}
                                    <div>
                                        <p style={{ color: "#ffffff", fontWeight: 800, fontSize: 13, margin: 0 }}>
                                            {f.title}
                                        </p>
                                        <p style={{ color: "rgba(255,255,255,0.85)", fontSize: 12, fontWeight: 600, margin: 0, marginTop: 2 }}>
                                            {f.desc}
                                        </p>
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>{/* end z-index content wrapper */}
                </div>

                {/* RIGHT PANEL */}
                <div className="w-full md:w-[50%]" style={{
                    background: "#ffffff",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    padding: "clamp(28px,4vw,44px)",
                    boxSizing: "border-box",
                }}>
                    <div style={{ width: "100%", maxWidth: 380 }}>

                        <h2 style={{ fontSize: 28, fontWeight: 800, color: "#0f172a", marginBottom: 32, textAlign: "center" }}>
                            Sign In
                        </h2>

                        {success && (
                            <div role="status" style={{ marginBottom: 20, padding: "10px 14px", borderRadius: 8, background: "#f0fdf4", border: "1px solid #bbf7d0", color: "#16a34a", fontSize: 13, fontWeight: 600 }}>
                                {success}
                            </div>
                        )}
                        {error && (
                            <div role="alert" style={{ marginBottom: 20, padding: "10px 14px", borderRadius: 8, background: "#fef2f2", border: "1px solid #fecaca", color: "#dc2626", fontSize: 13, fontWeight: 600 }}>
                                {error}
                            </div>
                        )}
                        {mfaRequired ? (
                            <form onSubmit={useRecoveryCode ? handleMfaRecover : handleMfaVerify} style={{ display: "flex", flexDirection: "column", gap: 20 }}>
                                <p style={{ fontSize: 14, color: "#374151" }}>
                                    {useRecoveryCode ? "Enter one of your 8-character backup recovery codes." : "Enter the 6-digit code from your Google Authenticator app."}
                                </p>

                                {!useRecoveryCode ? (
                                    <div>
                                        <label htmlFor="mfa-code" style={{ display: "block", marginBottom: 6, fontWeight: 600, color: "#374151", fontSize: 14 }}>
                                            Authenticator Code
                                        </label>
                                        <div style={{ display: "flex", alignItems: "center", border: "1px solid #e2e8f0", borderRadius: 10, background: "#f8fafc", padding: "0 14px", height: 48 }}>
                                            <input
                                                id="mfa-code"
                                                type="text"
                                                inputMode="numeric"
                                                autoComplete="one-time-code"
                                                placeholder="123456"
                                                value={mfaCode}
                                                onChange={(e) => setMfaCode(sanitizeAsciiSingleLine(e.target.value, 6, true))}
                                                required
                                                style={{ flex: 1, border: "none", background: "transparent", outline: "none", fontSize: 16, color: "#1e293b", fontWeight: 600, letterSpacing: 2 }}
                                            />
                                        </div>
                                    </div>
                                ) : (
                                    <div>
                                        <label htmlFor="mfa-recovery-code" style={{ display: "block", marginBottom: 6, fontWeight: 600, color: "#374151", fontSize: 14 }}>
                                            Recovery Code
                                        </label>
                                        <div style={{ display: "flex", alignItems: "center", border: "1px solid #e2e8f0", borderRadius: 10, background: "#f8fafc", padding: "0 14px", height: 48 }}>
                                            <input
                                                id="mfa-recovery-code"
                                                type="text"
                                                autoComplete="off"
                                                placeholder="abcdef12"
                                                value={recoveryInput}
                                                onChange={(e) => setRecoveryInput(sanitizeAsciiSingleLine(e.target.value, 16, true))}
                                                required
                                                style={{ flex: 1, border: "none", background: "transparent", outline: "none", fontSize: 16, color: "#1e293b", fontWeight: 600, letterSpacing: 2 }}
                                            />
                                        </div>
                                    </div>
                                )}

                                <button
                                    type="submit"
                                    disabled={loading}
                                    style={{
                                        width: "100%",
                                        background: loading ? "#93a6c4" : NAVY_DARK,
                                        color: "#ffffff",
                                        fontWeight: 700,
                                        padding: "14px 0",
                                        borderRadius: 10,
                                        fontSize: 15,
                                        border: "none",
                                        cursor: loading ? "not-allowed" : "pointer",
                                        display: "flex",
                                        alignItems: "center",
                                        justifyContent: "center",
                                        gap: 8,
                                        letterSpacing: "0.01em",
                                    }}
                                >
                                    {loading ? "Verifying..." : "Verify & Sign In →"}
                                </button>

                                <div style={{ textAlign: "center", marginTop: -8 }}>
                                    <button
                                        type="button"
                                        onClick={() => {
                                            setUseRecoveryCode(!useRecoveryCode);
                                            setError("");
                                        }}
                                        className="rounded-lg"
                                        style={{ background: "transparent", border: "0", outline: "none", boxShadow: "none", padding: 0, color: "#2563eb", fontSize: 13, fontWeight: 600, cursor: "pointer", textDecoration: "underline" }}
                                    >
                                        {useRecoveryCode ? "Use Authenticator App instead" : "Use a Recovery Code instead"}
                                    </button>
                                </div>
                            </form>
                        ) : (

                            <form onSubmit={handleLogin} style={{ display: "flex", flexDirection: "column", gap: 20 }}>

                                {/* Email */}
                                <div>
                                    <label htmlFor="login-email" style={{ display: "block", marginBottom: 6, fontWeight: 600, color: "#374151", fontSize: 14 }}>
                                        Your email
                                    </label>
                                    <div style={{ display: "flex", alignItems: "center", border: "1px solid #e2e8f0", borderRadius: 10, background: "#f8fafc", padding: "0 14px", gap: 10, height: 48 }}>
                                        <EnvelopeIcon style={{ width: 18, height: 18, color: "#94a3b8", flexShrink: 0 }} />
                                        <input
                                            id="login-email"
                                            type="email"
                                            placeholder="hi@vajra.io"
                                            value={email}
                                            onChange={(e) => setEmail(sanitizeAsciiSingleLine(e.target.value, 254, true))}
                                            required
                                            autoComplete="username"
                                            style={{ flex: 1, border: "none", background: "transparent", outline: "none", fontSize: 14, color: "#1e293b", fontWeight: 500 }}
                                        />
                                    </div>
                                </div>

                                {/* Password */}
                                <div>
                                    <label htmlFor="login-password" style={{ display: "block", marginBottom: 6, fontWeight: 600, color: "#374151", fontSize: 14 }}>
                                        Password
                                    </label>
                                    <div style={{ display: "flex", alignItems: "center", border: "1px solid #e2e8f0", borderRadius: 10, background: "#f8fafc", padding: "0 14px", gap: 10, height: 48 }}>
                                        <LockClosedIcon style={{ width: 18, height: 18, color: "#94a3b8", flexShrink: 0 }} />
                                        <input
                                            id="login-password"
                                            type={showPassword ? "text" : "password"}
                                            placeholder="••••••••••"
                                            value={password}
                                            onChange={(e) => setPassword(sanitizeAsciiSingleLine(e.target.value, 128, false))}
                                            required
                                            autoComplete="current-password"
                                            style={{ flex: 1, border: "none", background: "transparent", outline: "none", fontSize: 14, color: "#1e293b", fontWeight: 500 }}
                                        />
                                        <button
                                            type="button"
                                            onClick={() => setShowPassword(!showPassword)}
                                            aria-label={showPassword ? "Hide password" : "Show password"}
                                            aria-pressed={showPassword}
                                            className="rounded-lg"
                                            style={{ background: "none", border: "none", cursor: "pointer", color: "#94a3b8", display: "flex", padding: 0, flexShrink: 0 }}
                                        >
                                            {showPassword
                                                ? <EyeSlashIcon style={{ width: 18, height: 18 }} />
                                                : <EyeIcon style={{ width: 18, height: 18 }} />}
                                        </button>
                                    </div>
                                </div>

                                {/* Captcha */}
                                {captchaRequired && (
                                    <div>
                                        <label htmlFor="login-captcha" style={{ display: "block", marginBottom: 6, fontWeight: 600, color: "#374151", fontSize: 14 }}>
                                            Please verify you're human
                                        </label>
                                        {captchaImg && (
                                            <img
                                                src={captchaImg}
                                                alt="CAPTCHA"
                                                style={{ marginBottom: 8, maxWidth: 280, borderRadius: 8, border: "1px solid #e2e8f0" }}
                                            />
                                        )}
                                        <div style={{ display: "flex", alignItems: "center", border: "1px solid #e2e8f0", borderRadius: 10, background: "#f8fafc", padding: "0 14px", height: 48 }}>
                                            <input
                                                id="login-captcha"
                                                type="text"
                                                placeholder="Enter the text above"
                                                value={captchaInput}
                                                onChange={(e) => setCaptchaInput(sanitizeAsciiSingleLine(e.target.value, 16, true))}
                                                required
                                                style={{ flex: 1, border: "none", background: "transparent", outline: "none", fontSize: 14, color: "#1e293b" }}
                                            />
                                        </div>
                                    </div>
                                )}

                                {/* Forgot password — no self-service reset exists; accounts are provisioned by an admin */}
                                <div style={{ display: "flex", justifyContent: "flex-end", marginTop: -8 }}>
                                    <span style={{ fontSize: 13, color: "#64748b" }}>
                                        Forgot password? Contact your administrator.
                                    </span>
                                </div>

                                {/* Sign In button */}
                                <button
                                    type="submit"
                                    disabled={loading}
                                    style={{
                                        width: "100%",
                                        background: loading ? "#93a6c4" : NAVY_DARK,
                                        color: "#ffffff",
                                        fontWeight: 700,
                                        padding: "14px 0",
                                        borderRadius: 10,
                                        fontSize: 15,
                                        border: "none",
                                        cursor: loading ? "not-allowed" : "pointer",
                                        display: "flex",
                                        alignItems: "center",
                                        justifyContent: "center",
                                        gap: 8,
                                        letterSpacing: "0.01em",
                                    }}
                                >
                                    {loading ? "Signing In..." : "Sign In →"}
                                </button>

                            </form>
                        )}
                    </div>
                </div>

            </div>{/* end floating card */}
        </HexagonBackground>
    );
}
