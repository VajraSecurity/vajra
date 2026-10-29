import { useState, type CSSProperties, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  EyeIcon,
  EyeSlashIcon,
  UserIcon,
  EnvelopeIcon,
  LockClosedIcon,
  UserCircleIcon,
  PhoneIcon,
  ShieldCheckIcon,
  ComputerDesktopIcon,
  UserGroupIcon
} from "@heroicons/react/24/outline";
import { isAxiosError } from 'axios';
import { register } from '../../api/api';
import { useToast } from '../../context/useToast';
import { sanitizeAsciiSingleLine } from '../../services/inputSanitizers';
import vajraLogoWhite from "../../assets/vajra/vajralogo-white.png";
import { HexagonBackground } from "../../components/animate-ui/components/backgrounds/hexagon";
import SideRays from "../../components/SideRays/SideRays";

interface FormData {
  name: string;
  email: string;
  password: string;
  passwordConfirm: string;
  mobile: string;
  role: 'Super Administrator' | 'Group Admin' | 'Viewer';
  countryCode: string;
}

interface ValidationErrors {
  [key: string]: string;
}

const NAVY = "#1e3a8a";
const NAVY_DARK = "#172d6e";
const CARD_BG = "#1a3070";

const FEATURES = [
  {
    num: 1,
    Icon: ShieldCheckIcon,
    title: "Compliance Ready",
    desc: "ISO, SOC 2, and NIST compliance mapping out of the box.",
  },
  {
    num: 2,
    Icon: ComputerDesktopIcon,
    title: "24/7 Monitoring",
    desc: "Continuous threat detection and automated response.",
  },
  {
    num: 3,
    Icon: UserGroupIcon,
    title: "Expert Support",
    desc: "Dedicated security specialists on standby, always.",
  },
];

/* Shared field wrapper */
const fieldWrap: CSSProperties = {
  display: "flex",
  alignItems: "center",
  border: "1px solid #e2e8f0",
  borderRadius: 10,
  background: "#f8fafc",
  padding: "0 14px",
  gap: 10,
  height: 48,
  overflow: "hidden",
  width: "100%",
  boxSizing: "border-box",
};

const innerInput: CSSProperties = {
  flex: 1,
  minWidth: 0,
  border: "none",
  background: "transparent",
  outline: "none",
  fontSize: 14,
  color: "#1e293b",
  fontWeight: 500,
  width: "100%",
};

const labelSty: CSSProperties = {
  display: "block",
  marginBottom: 6,
  fontWeight: 600,
  color: "#374151",
  fontSize: 14,
};

const iconSty: CSSProperties = {
  width: 18,
  height: 18,
  color: "#94a3b8",
  flexShrink: 0,
};

const SignUpForm: React.FC = () => {
  const { showToast } = useToast();
  const navigate = useNavigate();
  const [showPwd, setShowPwd] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);
  const [loading, setLoading] = useState(false);
  const [errors, setErrors] = useState<ValidationErrors>({});

  const [formData, setFormData] = useState<FormData>({
    name: "",
    email: "",
    password: "",
    passwordConfirm: "",
    mobile: "",
    role: "Viewer",
    countryCode: "+91",
  });

  const handleChange = (
    e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>
  ) => {
    const { name, value } = e.target;
    const nextValue = (() => {
      switch (name) {
        case 'email': return sanitizeAsciiSingleLine(value, 254, true);
        case 'password':
        case 'passwordConfirm': return sanitizeAsciiSingleLine(value, 128, false);
        case 'mobile': return sanitizeAsciiSingleLine(value, 15, true).replace(/\D/g, '');
        case 'countryCode': return sanitizeAsciiSingleLine(value, 4, true);
        case 'name': return sanitizeAsciiSingleLine(value, 64, true);
        case 'role': return sanitizeAsciiSingleLine(value, 32, true);
        default: return sanitizeAsciiSingleLine(value, 256, true);
      }
    })();
    setFormData((prev) => ({ ...prev, [name]: nextValue }));
  };

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setErrors({});

    if (formData.password !== formData.passwordConfirm) {
      setErrors({ passwordConfirm: "Passwords do not match." });
      showToast("Passwords do not match.", "error");
      return;
    }

    setLoading(true);

    try {
      const payload = {
        name: formData.name,
        email: formData.email,
        password: formData.password,
        passwordConfirm: formData.passwordConfirm,
        mobile: `${formData.countryCode}${formData.mobile}`,
        role: formData.role,
      };

      const data = await register(payload);

      if (data.errorsValidation && Array.isArray(data.errorsValidation)) {
        const newErrors: ValidationErrors = {};
        data.errorsValidation.forEach((err) => {
          const key = Object.keys(err)[0];
          const message = err[key];
          newErrors[key] = message;
          showToast(message, "error");
        });
        setErrors(newErrors);
        return;
      }

      if (data.errorMessage) {
        showToast(data.errorMessage, "error");
        return;
      }

      if (data.status === "Success") {
        showToast("Account created successfully!", "success");
        setTimeout(() => { navigate("/dashboard"); }, 1200);
      }

    } catch (error) {
      const backendData = isAxiosError<{ errorsValidation?: Array<Record<string, string>>; message?: string }>(error)
        ? error.response?.data
        : undefined;
      if (backendData?.errorsValidation) {
        backendData.errorsValidation.forEach((err) => {
          const key = Object.keys(err)[0];
          showToast(err[key], "error");
        });
      } else {
        showToast(backendData?.message || "Something went wrong. Please try again.", "error");
      }
    } finally {
      setLoading(false);
    }
  };

  return (
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
        maxWidth: 1000,
        minHeight: 560,
        borderRadius: 20,
        overflow: "hidden",
        boxShadow: "0 20px 60px rgba(0,0,0,0.15)",
        flexDirection: "row",
      }}>

        {/* LEFT PANEL */}
        <div className="hidden md:flex" style={{
          position: "relative",
          width: "42%",
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
                src={vajraLogoWhite}
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
              Add a new team<br />member to Vajra.
            </h1>

            <p style={{
              color: "rgba(255,255,255,0.9)",
              fontSize: 14,
              lineHeight: 1.7,
              marginBottom: 36,
              fontWeight: 600,
            }}>
              Endpoint detection &amp; response<br />built for modern security teams.
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
          </div>
        </div>

        {/* RIGHT PANEL */}
        <div
          className="w-full md:w-[58%] overflow-y-auto [&::-webkit-scrollbar]:w-1.5 [&::-webkit-scrollbar-track]:bg-transparent [&::-webkit-scrollbar-thumb]:rounded-full [&::-webkit-scrollbar-thumb]:bg-blue-300 [&::-webkit-scrollbar-thumb:hover]:bg-blue-500"
          style={{
            background: "#ffffff",
            padding: "clamp(28px,4vw,44px) clamp(28px,4vw,44px)",
            boxSizing: "border-box",
            scrollbarWidth: "thin",
            scrollbarColor: "#93c5fd transparent",
          }}
        >
          <div style={{ width: "100%", maxWidth: 500, margin: "0 auto" }}>
            <h2 style={{ fontSize: 28, fontWeight: 800, color: "#0f172a", marginBottom: 6, textAlign: "center" }}>
              Create Team Member Account
            </h2>
            <p style={{ fontSize: 14, color: "#64748b", marginBottom: 28, textAlign: "center", fontWeight: 500 }}>
              Set up access for a new member of your organization.
            </p>

            <form
              onSubmit={handleSubmit}
              className="grid grid-cols-1 lg:grid-cols-2"
              style={{
                gap: "18px 14px",
              }}
            >
              {/* Full Name */}
              <div>
                <label htmlFor="signup-name" style={labelSty}>Full Name</label>
                <div style={fieldWrap}>
                  <UserIcon style={iconSty} />
                  <input
                    id="signup-name"
                    type="text"
                    name="name"
                    value={formData.name}
                    onChange={handleChange}
                    placeholder="Name"
                    autoComplete="name"
                    required
                    aria-invalid={!!errors.name}
                    aria-describedby={errors.name ? "signup-name-error" : undefined}
                    style={innerInput}
                  />
                </div>
                {errors.name && <p id="signup-name-error" role="alert" style={{ color: "#dc2626", fontSize: 11.5, marginTop: 3 }}>{errors.name}</p>}
              </div>

              {/* Email */}
              <div>
                <label htmlFor="signup-email" style={labelSty}>Email Address</label>
                <div style={fieldWrap}>
                  <EnvelopeIcon style={iconSty} />
                  <input
                    id="signup-email"
                    type="email"
                    name="email"
                    value={formData.email}
                    onChange={handleChange}
                    placeholder="email@vajra.io"
                    autoComplete="email"
                    required
                    aria-invalid={!!errors.email}
                    aria-describedby={errors.email ? "signup-email-error" : undefined}
                    style={innerInput}
                  />
                </div>
                {errors.email && <p id="signup-email-error" role="alert" style={{ color: "#dc2626", fontSize: 11.5, marginTop: 3 }}>{errors.email}</p>}
              </div>

              {/* Password */}
              <div>
                <label htmlFor="signup-password" style={labelSty}>Password</label>
                <div style={fieldWrap}>
                  <LockClosedIcon style={iconSty} />
                  <input
                    id="signup-password"
                    type={showPwd ? "text" : "password"}
                    name="password"
                    value={formData.password}
                    onChange={handleChange}
                    placeholder="••••••••"
                    autoComplete="new-password"
                    required
                    aria-invalid={!!errors.password}
                    aria-describedby={errors.password ? "signup-password-error" : undefined}
                    style={innerInput}
                  />
                  <button
                    type="button"
                    onClick={() => setShowPwd(!showPwd)}
                    aria-label={showPwd ? "Hide password" : "Show password"}
                    aria-pressed={showPwd}
                    className="rounded-lg"
                    style={{ background: "none", border: "none", cursor: "pointer", color: "#94a3b8", display: "flex", padding: 0 }}
                  >
                    {showPwd ? <EyeSlashIcon style={iconSty} /> : <EyeIcon style={iconSty} />}
                  </button>
                </div>
                {errors.password && <p id="signup-password-error" role="alert" style={{ color: "#dc2626", fontSize: 11.5, marginTop: 3 }}>{errors.password}</p>}
              </div>

              {/* Confirm Password */}
              <div>
                <label htmlFor="signup-password-confirm" style={labelSty}>Confirm Password</label>
                <div style={fieldWrap}>
                  <LockClosedIcon style={iconSty} />
                  <input
                    id="signup-password-confirm"
                    type={showConfirm ? "text" : "password"}
                    name="passwordConfirm"
                    value={formData.passwordConfirm}
                    onChange={handleChange}
                    placeholder="••••••••"
                    autoComplete="new-password"
                    required
                    aria-invalid={!!errors.passwordConfirm}
                    aria-describedby={errors.passwordConfirm ? "signup-password-confirm-error" : undefined}
                    style={innerInput}
                  />
                  <button
                    type="button"
                    onClick={() => setShowConfirm(!showConfirm)}
                    aria-label={showConfirm ? "Hide password" : "Show password"}
                    aria-pressed={showConfirm}
                    className="rounded-lg"
                    style={{ background: "none", border: "none", cursor: "pointer", color: "#94a3b8", display: "flex", padding: 0 }}
                  >
                    {showConfirm ? <EyeSlashIcon style={iconSty} /> : <EyeIcon style={iconSty} />}
                  </button>
                </div>
                {errors.passwordConfirm && <p id="signup-password-confirm-error" role="alert" style={{ color: "#dc2626", fontSize: 11.5, marginTop: 3 }}>{errors.passwordConfirm}</p>}
              </div>

              {/* Role */}
              <div className="lg:col-span-2">
                <label htmlFor="signup-role" style={labelSty}>Role</label>
                <div style={fieldWrap}>
                  <UserCircleIcon style={iconSty} />
                  <select
                    id="signup-role"
                    name="role"
                    value={formData.role}
                    onChange={handleChange}
                    required
                    aria-invalid={!!errors.role}
                    aria-describedby={errors.role ? "signup-role-error signup-role-help" : "signup-role-help"}
                    style={{
                      ...innerInput,
                      appearance: "none",
                      WebkitAppearance: "none",
                      MozAppearance: "none",
                    }}
                  >
                    <option value="Super Administrator">Super Administrator</option>
                    <option value="Group Admin">Group Admin</option>
                    <option value="Viewer">Viewer</option>
                  </select>
                </div>
                <p id="signup-role-help" style={{ fontSize: 11.5, color: "#64748b", marginTop: 3 }}>
                  Super Administrator: full access, including Remote Shell and Policy Management. Group Admin: manages endpoints and policies for assigned groups. Viewer: read-only access to dashboards and reports.
                </p>
                {errors.role && <p id="signup-role-error" role="alert" style={{ color: "#dc2626", fontSize: 11.5, marginTop: 3 }}>{errors.role}</p>}
              </div>

              {/* Phone */}
              <div className="lg:col-span-2">
                <label htmlFor="signup-mobile" style={labelSty}>Phone Number</label>
                <div style={fieldWrap}>
                  <PhoneIcon style={iconSty} />
                  {/* Only +91 is offered: the backend validates mobile numbers
                      against the en-IN format regardless of country code, so
                      any other prefix would always be rejected. */}
                  <span style={{ fontSize: 14, color: "#1e293b", fontWeight: 500 }}>+91</span>
                  <input
                    id="signup-mobile"
                    type="tel"
                    name="mobile"
                    value={formData.mobile}
                    onChange={handleChange}
                    placeholder="987654321"
                    autoComplete="tel-national"
                    required
                    aria-invalid={!!errors.mobile}
                    aria-describedby={errors.mobile ? "signup-mobile-error" : undefined}
                    style={innerInput}
                  />
                </div>
                {errors.mobile && <p id="signup-mobile-error" role="alert" style={{ color: "#dc2626", fontSize: 11.5, marginTop: 3 }}>{errors.mobile}</p>}
              </div>

              {/* Cancel and return */}
              <div className="lg:col-span-2" style={{ display: "flex", justifyContent: "center", marginTop: 4 }}>
                <p style={{ fontSize: 14, color: "#475569", margin: 0 }}>
                  <Link to="/management" style={{ color: "#2563eb", fontWeight: 600, textDecoration: "none" }}>
                    ← Cancel and return to Team Management
                  </Link>
                </p>
              </div>

              {/* Submit */}
              <div className="lg:col-span-2" style={{ marginTop: 8 }}>
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
                    letterSpacing: "0.01em",
                  }}
                >
                  {loading ? "Creating Account..." : "Create Account →"}
                </button>
              </div>

            </form>
          </div>
        </div>
      </div>
    </HexagonBackground>
  );
};

export default SignUpForm;