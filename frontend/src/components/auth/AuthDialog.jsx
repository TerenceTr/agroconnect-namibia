// ====================================================================
// frontend/src/components/auth/AuthDialog.jsx
// --------------------------------------------------------------------
// FILE ROLE:
//   Shared authentication dialog for the public Start page.
//
// WHAT THIS VERSION IMPROVES:
//   • removes duplicated visual blocks between left and right panels
//   • shifts the dialog to a balanced mid-light premium surface
//   • keeps emerald for actions and gold only for customer emphasis
//   • reduces oversized headings and overly bright glass layers
//   • simplifies login / forgot / register layouts for easier scanning
//   • preserves flexible auth-handler support from props or provider
//   • sends numeric role IDs expected by the current backend/auth provider
// ====================================================================

import React, { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ArrowLeft,
  ArrowRight,  LogIn,
  Mail,  ShoppingCart,  Tractor,  X,
} from 'lucide-react';
import { useAuth } from './AuthProvider';

// --------------------------------------------------------------------
// Small className combiner.
// --------------------------------------------------------------------
function cx(...parts) {
  return parts.filter(Boolean).join(' ');
}

// --------------------------------------------------------------------
// Backend / auth-provider role mapping.
// Current project expects numeric role IDs:
//   admin    = 1
//   farmer   = 2
//   customer = 3
// --------------------------------------------------------------------
function roleStringToId(roleLike) {
  const role = String(roleLike || '').trim().toLowerCase();
  if (role === 'admin') return 1;
  if (role === 'farmer' || role === 'seller') return 2;
  return 3;
}

// --------------------------------------------------------------------
// Resolve dashboard route from role name or role ID.
// --------------------------------------------------------------------
function resolveDashboardRoute(roleLike) {
  const value = String(roleLike ?? '').trim().toLowerCase();

  if (value === '1' || value === 'admin') return '/dashboard/admin';
  if (value === '2' || value === 'farmer' || value === 'seller') {
    return '/dashboard/farmer/overview';
  }

  return '/dashboard/customer';
}

// --------------------------------------------------------------------
// Best-effort role extraction from different auth payload shapes.
// --------------------------------------------------------------------
function extractRoleFromResult(result, fallbackRole = 'customer') {
  const rawRole =
    result?.role ??
    result?.role_name ??
    result?.user?.role ??
    result?.user?.role_name ??
    result?.data?.role ??
    result?.data?.role_name ??
    result?.data?.user?.role ??
    result?.data?.user?.role_name ??
    result?.profile?.role ??
    result?.profile?.role_name ??
    result?.account?.role ??
    result?.account?.role_name ??
    fallbackRole;

  return String(rawRole || fallbackRole).toLowerCase();
}

// --------------------------------------------------------------------
// Finds the first available function from a list.
// --------------------------------------------------------------------
function findFirstFunction(...candidates) {
  return candidates.find((fn) => typeof fn === 'function') || null;
}

// --------------------------------------------------------------------
// Some auth providers accept object payloads, others positional args.
// --------------------------------------------------------------------
async function invokeFlexible(handler, payload) {
  if (typeof handler !== 'function') return null;

  try {
    return await handler(payload);
  } catch (firstError) {
    if (payload && typeof payload === 'object') {
      try {
        return await handler(...Object.values(payload));
      } catch (secondError) {
        throw secondError;
      }
    }

    throw firstError;
  }
}

// --------------------------------------------------------------------
// Parse incoming mode into stable internal state.
// Supported:
//   login
//   forgot
//   register-customer
//   register-farmer
// --------------------------------------------------------------------
function parseDialogMode(mode) {
  const raw = String(mode || 'login').toLowerCase();

  if (raw.includes('forgot')) {
    return { baseMode: 'forgot', role: 'customer' };
  }

  if (raw.includes('register') || raw.includes('signup') || raw.includes('sign-up')) {
    if (raw.includes('farmer') || raw.includes('seller')) {
      return { baseMode: 'register', role: 'farmer' };
    }

    return { baseMode: 'register', role: 'customer' };
  }

  return { baseMode: 'login', role: 'customer' };
}

// --------------------------------------------------------------------
// Shared visual tokens.
// Balanced surface: no heavy dark shell, but also not overly bright.
// --------------------------------------------------------------------
const MODAL_SHELL =
  'bg-[linear-gradient(135deg,rgba(244,248,245,0.96),rgba(232,240,235,0.94))]';

const SHELL_FRAME =
  'border border-white/55 shadow-[0_30px_90px_rgba(6,24,16,0.18)] backdrop-blur-2xl';

const LEFT_PANEL =
  'bg-[linear-gradient(180deg,rgba(235,243,238,0.94),rgba(224,235,228,0.90))]';

const RIGHT_PANEL =
  'bg-[linear-gradient(180deg,rgba(246,249,247,0.96),rgba(236,243,238,0.94))]';

const PANEL_CARD =
  'rounded-[26px] border border-[#D6E4DB] bg-[rgba(255,255,255,0.74)] shadow-[0_14px_34px_rgba(9,30,20,0.06)]';


const PAGE_TEXT = 'text-[#173324]';
const MUTED_TEXT = 'text-[#61796B]';

const PRIMARY_BUTTON =
  'bg-[#2D8B57] text-white hover:bg-[#309A60] focus:ring-4 focus:ring-emerald-300/35';

const SECONDARY_BUTTON =
  'border border-[#D6E4DB] bg-white/88 text-[#173324] hover:bg-[#F3F8F5] focus:ring-4 focus:ring-emerald-200/35';

const CUSTOMER_BUTTON = 'bg-[#C9A85A] text-[#172317] hover:bg-[#D4B56A]';
const FARMER_BUTTON = 'bg-[#2D6A4F] text-white hover:bg-[#34785A]';

const FIELD_CLASS =
  'w-full rounded-2xl border border-[#D6E4DB] bg-white/96 px-4 py-3 text-sm text-[#173324] outline-none transition placeholder:text-slate-400 focus:border-emerald-500/55 focus:ring-4 focus:ring-emerald-200/45';

// --------------------------------------------------------------------
// Reusable input field.
// --------------------------------------------------------------------
function DialogField({
  label,
  type = 'text',
  value,
  onChange,
  placeholder,
  helperText = '',
  error = '',
  autoComplete,
  showToggle = false,
}) {
  const [reveal, setReveal] = useState(false);
  const isPassword = type === 'password';
  const inputType = showToggle && isPassword ? (reveal ? 'text' : 'password') : type;

  return (
    <div className="space-y-1.5">
      {label ? <label className="block text-[13px] font-semibold text-[#173324]">{label}</label> : null}

      <div className="relative">
        <input
          type={inputType}
          value={value}
          onChange={onChange}
          placeholder={placeholder}
          autoComplete={autoComplete}
          className={cx(
            FIELD_CLASS,
            showToggle ? 'pr-14' : '',
            error ? 'border-rose-400 focus:border-rose-400 focus:ring-rose-200/45' : ''
          )}
        />

        {showToggle && isPassword ? (
          <button
            type="button"
            onClick={() => setReveal((current) => !current)}
            className="absolute right-2 top-1/2 flex h-9 w-9 -translate-y-1/2 items-center justify-center rounded-full border border-[#D6E4DB] bg-[#F7FAF8] text-slate-600 transition hover:bg-[#EEF5F1]"
            aria-label={reveal ? 'Hide password' : 'Show password'}
          >
            <span className="text-sm">{reveal ? '🙈' : '👁'}</span>
          </button>
        ) : null}
      </div>

      {error ? (
        <p className="text-xs font-medium text-rose-500">{error}</p>
      ) : helperText ? (
        <p className="text-xs text-[#6A8174]">{helperText}</p>
      ) : null}
    </div>
  );
}

// --------------------------------------------------------------------
// Single brand badge kept only on the left panel to avoid duplication.
// --------------------------------------------------------------------
function BrandBadge() {
  return (
    <div className="inline-flex items-center gap-3 rounded-full border border-white/75 bg-white/92 px-4 py-2 shadow-[0_10px_24px_rgba(9,30,20,0.07)]">
      <div className="flex h-10 w-10 items-center justify-center rounded-full bg-[#2D6A4F] text-sm font-black text-white">
        AC
      </div>

      <div className="min-w-0">
        <div className="text-[10px] font-black uppercase tracking-[0.22em] text-[#6A7E72]">
          Public marketplace
        </div>
        <div className="mt-0.5 text-[14px] font-semibold leading-none text-[#173324]">
          AgroConnect Namibia
        </div>
      </div>
    </div>
  );
}

// --------------------------------------------------------------------
// Small mode pill.
// --------------------------------------------------------------------
function ModePill({ children }) {
  return (
    <div className="inline-flex items-center rounded-full border border-[#D4E2D9] bg-white/88 px-3 py-1 text-[10px] font-black uppercase tracking-[0.2em] text-[#587062]">
      {children}
    </div>
  );
}

// --------------------------------------------------------------------
// Left-panel feature row.
// --------------------------------------------------------------------
function FeatureTile({ icon: Icon, text }) {
  return (
    <div className="flex items-center gap-3 rounded-2xl border border-white/75 bg-white/76 px-4 py-3.5 shadow-[0_8px_18px_rgba(9,30,20,0.04)]">
      <div className="flex h-9 w-9 items-center justify-center rounded-full border border-[#D6E4DB] bg-[#F3F8F5] text-[#2D6A4F]">
        <Icon size={17} />
      </div>
      <div className="text-[13px] font-semibold leading-6 text-[#173324]">{text}</div>
    </div>
  );
}

// --------------------------------------------------------------------
// Registration stepper.
// --------------------------------------------------------------------
function Stepper({ step }) {
  const items = [
    { id: 1, label: 'Account details' },
    { id: 2, label: 'Security' },
  ];

  return (
    <div className={cx(PANEL_CARD, 'flex items-center gap-3 px-4 py-3')}>
      {items.map((item, index) => {
        const active = step === item.id;
        const completed = step > item.id;

        return (
          <React.Fragment key={item.id}>
            <div className="flex items-center gap-3">
              <div
                className={cx(
                  'flex h-7 w-7 items-center justify-center rounded-full text-[11px] font-black',
                  active || completed ? 'bg-[#2D8B57] text-white' : 'bg-[#EAF1EC] text-[#6A8174]'
                )}
              >
                {item.id}
              </div>
              <span className={cx('text-[13px] font-semibold', active ? PAGE_TEXT : MUTED_TEXT)}>
                {item.label}
              </span>
            </div>

            {index < items.length - 1 ? <div className="h-px flex-1 bg-[#DCE8E0]" /> : null}
          </React.Fragment>
        );
      })}
    </div>
  );
}

// --------------------------------------------------------------------
// Role selector.
// --------------------------------------------------------------------
function RoleSwitch({ role, onChange }) {
  const isFarmer = role === 'farmer';

  return (
    <div className={cx(PANEL_CARD, 'p-4')}>
      <div>
        <div className="text-[15px] font-bold text-[#173324]">Account type</div>
        <p className="mt-1 text-[13px] text-[#5F776A]">
          Choose the workspace you want to create.
        </p>
      </div>

      <div className="mt-4 grid grid-cols-2 gap-2 rounded-[18px] border border-[#D6E4DB] bg-[#F6FAF8] p-1.5">
        <button
          type="button"
          onClick={() => onChange('farmer')}
          className={cx(
            'inline-flex items-center justify-center gap-2 rounded-2xl px-4 py-3 text-sm font-semibold transition',
            isFarmer ? FARMER_BUTTON : SECONDARY_BUTTON
          )}
        >
          <Tractor size={16} />
          Farmer
        </button>

        <button
          type="button"
          onClick={() => onChange('customer')}
          className={cx(
            'inline-flex items-center justify-center gap-2 rounded-2xl px-4 py-3 text-sm font-semibold transition',
            !isFarmer ? CUSTOMER_BUTTON : SECONDARY_BUTTON
          )}
        >
          <ShoppingCart size={16} />
          Customer
        </button>
      </div>
    </div>
  );
}


// --------------------------------------------------------------------
// Main dialog.
// --------------------------------------------------------------------
export default function AuthDialog({
  open = false,
  mode = 'login',
  onClose,
  onModeChange,
  onBackToWebsite,
  onLoginSubmit,
  onRegisterSubmit,
  onForgotSubmit,
}) {
  const navigate = useNavigate();
  const auth = useAuth();

  const parsedMode = useMemo(() => parseDialogMode(mode), [mode]);
  const [registerRole, setRegisterRole] = useState(parsedMode.role);
  const [registerStep, setRegisterStep] = useState(1);

  const [busy, setBusy] = useState(false);
  const [flash, setFlash] = useState({ type: '', text: '' });

  const [loginForm, setLoginForm] = useState({
    email: '',
    password: '',
  });

  const [forgotForm, setForgotForm] = useState({
    email: '',
  });

  const [registerForm, setRegisterForm] = useState({
    fullName: '',
    email: '',
    phone: '',
    location: '',
    password: '',
    confirmPassword: '',
  });

  const [errors, setErrors] = useState({});

  // ----------------------------------------------------------------
  // Reset step-specific state whenever the dialog mode changes.
  // ----------------------------------------------------------------
  useEffect(() => {
    if (!open) return;

    setRegisterRole(parsedMode.role);
    setRegisterStep(1);
    setFlash({ type: '', text: '' });
    setErrors({});
  }, [open, parsedMode.role, parsedMode.baseMode]);

  // ----------------------------------------------------------------
  // Lock body scroll while the dialog is open.
  // ----------------------------------------------------------------
  useEffect(() => {
    if (!open || typeof document === 'undefined') return undefined;

    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';

    return () => {
      document.body.style.overflow = previousOverflow;
    };
  }, [open]);

  // ----------------------------------------------------------------
  // ESC closes the dialog.
  // ----------------------------------------------------------------
  useEffect(() => {
    if (!open || typeof window === 'undefined') return undefined;

    const handleKeyDown = (event) => {
      if (event.key === 'Escape') onClose?.();
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [open, onClose]);

  // ----------------------------------------------------------------
  // Mode-specific copy.
  // ----------------------------------------------------------------
  const currentCopy = useMemo(() => {
    if (parsedMode.baseMode === 'forgot') {
      return {
        modePill: 'Account recovery',
        leftTitle: 'Recover your account access.',
        leftBody:
          'Use your account email to receive the next reset step.',
        leftFeatures: [],
        rightTitle: 'Reset your password',
        rightDescription: 'Enter your email address and we will send the next secure step.',
      };
    }

    if (parsedMode.baseMode === 'register' && registerRole === 'farmer') {
      return {
        modePill: 'Seller onboarding',
        leftTitle: 'Create your farmer account.',
        leftBody:
          'Set up your seller account and continue into the farmer workspace.',
        leftFeatures: [],
        rightTitle: 'Create your account',
        rightDescription: 'Enter the essentials first, then secure your account in the next step.',
      };
    }

    if (parsedMode.baseMode === 'register' && registerRole === 'customer') {
      return {
        modePill: 'Buyer onboarding',
        leftTitle: 'Create your customer account.',
        leftBody:
          'Set up your buyer account and continue browsing with your own workspace.',
        leftFeatures: [],
        rightTitle: 'Create your account',
        rightDescription: 'Enter the essentials first, then secure your account in the next step.',
      };
    }

    return {
      modePill: 'Secure access',
      leftTitle: 'Sign in and continue.',
      leftBody:
        'Use your AgroConnect account to open the correct dashboard from the marketplace.',
      leftFeatures: [],
      rightTitle: 'Welcome back',
      rightDescription: 'Use your AgroConnect credentials to continue into the correct workspace.',
    };
  }, [parsedMode.baseMode, registerRole]);

  // ----------------------------------------------------------------
  // Validation.
  // ----------------------------------------------------------------
  const validateLogin = () => {
    const next = {};
    if (!loginForm.email.trim()) next.email = 'Email address is required.';
    if (!loginForm.password.trim()) next.password = 'Password is required.';
    return next;
  };

  const validateForgot = () => {
    const next = {};
    if (!forgotForm.email.trim()) next.email = 'Email address is required.';
    return next;
  };

  const validateRegisterStepOne = () => {
    const next = {};
    if (!registerForm.fullName.trim()) next.fullName = 'Full name is required.';
    if (!registerForm.email.trim()) next.email = 'Email address is required.';
    if (!registerForm.phone.trim()) next.phone = 'Phone number is required.';
    if (!registerForm.location.trim()) next.location = 'Location is required.';
    return next;
  };

  const validateRegisterStepTwo = () => {
    const next = {};

    if (!registerForm.password.trim()) {
      next.password = 'Password is required.';
    } else if (registerForm.password.trim().length < 6) {
      next.password = 'Password must be at least 6 characters.';
    }

    if (!registerForm.confirmPassword.trim()) {
      next.confirmPassword = 'Confirm your password.';
    } else if (registerForm.password !== registerForm.confirmPassword) {
      next.confirmPassword = 'Passwords do not match.';
    }

    return next;
  };

  // ----------------------------------------------------------------
  // Auth handlers from props or provider.
  // ----------------------------------------------------------------
  const loginHandler = findFirstFunction(
    onLoginSubmit,
    auth?.login,
    auth?.signIn,
    auth?.loginUser
  );

  const registerHandler = findFirstFunction(
    onRegisterSubmit,
    auth?.register,
    auth?.registerUser,
    auth?.signUp,
    auth?.signup
  );

  const forgotHandler = findFirstFunction(
    onForgotSubmit,
    auth?.forgotPassword,
    auth?.requestPasswordReset,
    auth?.sendResetLink,
    auth?.forgot
  );

  // ----------------------------------------------------------------
  // Field setters.
  // ----------------------------------------------------------------
  const setLoginField = (key) => (event) =>
    setLoginForm((current) => ({ ...current, [key]: event.target.value }));

  const setForgotField = (key) => (event) =>
    setForgotForm((current) => ({ ...current, [key]: event.target.value }));

  const setRegisterField = (key) => (event) =>
    setRegisterForm((current) => ({ ...current, [key]: event.target.value }));

  // ----------------------------------------------------------------
  // Mode switches.
  // ----------------------------------------------------------------
  const goToLogin = () => onModeChange?.('login');
  const goToForgot = () => onModeChange?.('forgot');
  const goToRegisterCustomer = () => onModeChange?.('register-customer');

  // ----------------------------------------------------------------
  // Submit: login.
  // ----------------------------------------------------------------
  const handleLogin = async (event) => {
    event.preventDefault();
    const nextErrors = validateLogin();
    setErrors(nextErrors);
    setFlash({ type: '', text: '' });

    if (Object.keys(nextErrors).length > 0) return;

    if (!loginHandler) {
      setFlash({
        type: 'error',
        text: 'Login handler is not available in the current auth setup.',
      });
      return;
    }

    setBusy(true);

    try {
      const result = await invokeFlexible(loginHandler, {
        email: loginForm.email.trim(),
        password: loginForm.password,
      });

      const role = extractRoleFromResult(result, 'customer');
      navigate(resolveDashboardRoute(role));
      onClose?.();
    } catch (error) {
      setFlash({
        type: 'error',
        text:
          error?.response?.data?.message ||
          error?.message ||
          'We could not sign you in. Please check your credentials and try again.',
      });
    } finally {
      setBusy(false);
    }
  };

  // ----------------------------------------------------------------
  // Submit: forgot password.
  // ----------------------------------------------------------------
  const handleForgot = async (event) => {
    event.preventDefault();
    const nextErrors = validateForgot();
    setErrors(nextErrors);
    setFlash({ type: '', text: '' });

    if (Object.keys(nextErrors).length > 0) return;

    if (!forgotHandler) {
      setFlash({
        type: 'error',
        text: 'Password recovery is not available in the current auth setup.',
      });
      return;
    }

    setBusy(true);

    try {
      await invokeFlexible(forgotHandler, {
        email: forgotForm.email.trim(),
      });

      setFlash({
        type: 'success',
        text: 'Reset instructions were prepared successfully. Check your email for the next step.',
      });
    } catch (error) {
      setFlash({
        type: 'error',
        text:
          error?.response?.data?.message ||
          error?.message ||
          'We could not prepare the reset step right now.',
      });
    } finally {
      setBusy(false);
    }
  };

  // ----------------------------------------------------------------
  // Registration step controls.
  // ----------------------------------------------------------------
  const handleRegisterNext = () => {
    const nextErrors = validateRegisterStepOne();
    setErrors(nextErrors);

    if (Object.keys(nextErrors).length > 0) return;
    setRegisterStep(2);
  };

  const handleRegister = async (event) => {
    event.preventDefault();

    const stepOneErrors = validateRegisterStepOne();
    const stepTwoErrors = validateRegisterStepTwo();
    const nextErrors = { ...stepOneErrors, ...stepTwoErrors };

    setErrors(nextErrors);
    setFlash({ type: '', text: '' });

    if (Object.keys(nextErrors).length > 0) {
      if (Object.keys(stepOneErrors).length > 0) setRegisterStep(1);
      return;
    }

    if (!registerHandler) {
      setFlash({
        type: 'error',
        text: 'Registration handler is not available in the current auth setup.',
      });
      return;
    }

    setBusy(true);

    try {
      const roleId = roleStringToId(registerRole);

      const payload = {
        full_name: registerForm.fullName.trim(),
        fullName: registerForm.fullName.trim(),
        email: registerForm.email.trim(),
        phone: registerForm.phone.trim(),
        phone_number: registerForm.phone.trim(),
        location: registerForm.location.trim(),
        password: registerForm.password,
        confirm_password: registerForm.confirmPassword,
        confirmPassword: registerForm.confirmPassword,
        role: roleId,
        role_id: roleId,
        role_name: registerRole,
      };

      const result = await invokeFlexible(registerHandler, payload);
      const role = extractRoleFromResult(result, registerRole);

      navigate(resolveDashboardRoute(role));
      onClose?.();
    } catch (error) {
      setFlash({
        type: 'error',
        text:
          error?.response?.data?.message ||
          error?.message ||
          'We could not create the account right now.',
      });
    } finally {
      setBusy(false);
    }
  };

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 sm:p-6">
      {/* ----------------------------------------------------------
          Overlay
      ----------------------------------------------------------- */}
      <button
        type="button"
        aria-label="Close auth dialog"
        onClick={onClose}
        className="absolute inset-0 bg-[rgba(13,26,19,0.20)] backdrop-blur-[7px]"
      />

      {/* ----------------------------------------------------------
          Modal shell
      ----------------------------------------------------------- */}
      <div
        className={cx(
          'relative grid w-full max-w-[1120px] overflow-hidden rounded-[32px]',
          'max-h-[92vh] lg:grid-cols-[320px_minmax(0,1fr)]',
          MODAL_SHELL,
          SHELL_FRAME
        )}
      >
        {/* ========================================================
            LEFT PANEL
        ========================================================= */}
        <aside className={cx('relative overflow-y-auto border-r border-white/40', LEFT_PANEL)}>
          <div className="pointer-events-none absolute -left-16 top-10 h-64 w-64 rounded-full bg-emerald-300/10 blur-3xl" />
          <div className="pointer-events-none absolute bottom-10 right-0 h-52 w-52 rounded-full bg-amber-200/10 blur-3xl" />

          <div className="relative flex min-h-full flex-col p-5 lg:p-6">
            <div className="flex justify-end">
              <button
                type="button"
                onClick={onBackToWebsite || onClose}
                className="inline-flex items-center gap-2 rounded-full border border-[#D6E4DB] bg-white/90 px-4 py-2 text-[12px] font-semibold text-[#173324] transition hover:bg-white"
              >
                Back to website
                <ArrowRight size={14} />
              </button>
            </div>

            <div className={cx('mt-6 flex-1 p-5', PANEL_CARD)}>
              <BrandBadge />

              <h2 className="mt-8 max-w-[14ch] text-[28px] font-black leading-[1.08] text-[#173324] sm:text-[34px]">
                {currentCopy.leftTitle}
              </h2>

              <p className="mt-5 max-w-[34ch] text-[14px] leading-7 text-[#446054]">
                {currentCopy.leftBody}
              </p>

              {currentCopy.leftFeatures?.length ? (
                <div className="mt-7 grid gap-3">
                  {currentCopy.leftFeatures.map((item) => (
                    <FeatureTile key={item.text} icon={item.icon} text={item.text} />
                  ))}
                </div>
              ) : null}
            </div>
          </div>
        </aside>

        {/* ========================================================
            RIGHT PANEL
        ========================================================= */}
        <section className={cx('relative overflow-y-auto p-5 lg:p-7', RIGHT_PANEL)}>
          <div className="pointer-events-none absolute right-0 top-0 h-40 w-40 rounded-full bg-emerald-200/10 blur-3xl" />
          <div className="pointer-events-none absolute bottom-0 left-0 h-44 w-44 rounded-full bg-white/30 blur-3xl" />

          <button
            type="button"
            onClick={onClose}
            className="absolute right-4 top-4 flex h-11 w-11 items-center justify-center rounded-full border border-[#D6E4DB] bg-white/86 text-[#173324] transition hover:bg-white"
            aria-label="Close dialog"
          >
            <X size={18} />
          </button>

          <div className="relative mx-auto w-full max-w-[720px]">
            <div className="flex justify-center">
              <ModePill>{currentCopy.modePill}</ModePill>
            </div>

            <h1 className="mt-5 text-center text-[34px] font-black leading-[1.05] text-[#173324] sm:text-[46px]">
              {currentCopy.rightTitle}
            </h1>

            {flash.text ? (
              <div
                className={cx(
                  'mt-4 rounded-2xl border px-4 py-3 text-sm font-medium',
                  flash.type === 'error'
                    ? 'border-rose-300 bg-rose-50 text-rose-700'
                    : 'border-emerald-300 bg-emerald-50 text-emerald-700'
                )}
              >
                {flash.text}
              </div>
            ) : null}

            {/* =====================================================
                LOGIN
            ====================================================== */}
            {parsedMode.baseMode === 'login' ? (
              <form onSubmit={handleLogin} className={cx('mt-5 p-5 lg:p-6', PANEL_CARD)}>
                <div className="text-[16px] font-bold text-[#173324]">Sign in</div>

                <div className="mt-4 grid gap-4">
                  <DialogField
                    label="Email address"
                    value={loginForm.email}
                    onChange={setLoginField('email')}
                    placeholder="example@example.com"
                    autoComplete="email"
                    error={errors.email}
                  />

                  <DialogField
                    label="Password"
                    type="password"
                    value={loginForm.password}
                    onChange={setLoginField('password')}
                    placeholder="Enter your password"
                    autoComplete="current-password"
                    showToggle
                    error={errors.password}
                  />
                </div>

                <button
                  type="submit"
                  disabled={busy}
                  className={cx(
                    'mt-5 inline-flex w-full items-center justify-center gap-2 rounded-2xl px-5 py-3.5 text-sm font-semibold transition',
                    busy ? 'cursor-not-allowed opacity-70' : '',
                    PRIMARY_BUTTON
                  )}
                >
                  <LogIn size={16} />
                  {busy ? 'Signing in...' : 'Sign in'}
                </button>

                <div className="mt-4 flex flex-col items-center gap-2 text-[13px]">
                  <button
                    type="button"
                    onClick={goToForgot}
                    className="font-semibold text-[#496256] underline underline-offset-2 transition hover:text-[#2D6A4F]"
                  >
                    Forgot password?
                  </button>

                  <div className="flex flex-wrap items-center justify-center gap-1 text-[#61796B]">
                    <span>Don’t have an account?</span>
                    <button
                      type="button"
                      onClick={goToRegisterCustomer}
                      className="font-semibold text-[#173324] underline underline-offset-2 transition hover:text-[#2D6A4F]"
                    >
                      Register
                    </button>
                  </div>
                </div>
              </form>
            ) : null}

            {/* =====================================================
                FORGOT PASSWORD
            ====================================================== */}
            {parsedMode.baseMode === 'forgot' ? (
              <form onSubmit={handleForgot} className={cx('mt-5 p-5 lg:p-6', PANEL_CARD)}>
                <div className="text-[16px] font-bold text-[#173324]">Password recovery</div>
                <p className="mt-1.5 text-[13px] leading-6 text-[#5B7366]">
                  Enter your email address and we will send the reset link.
                </p>

                <div className="mt-5">
                  <DialogField
                    label="Email address"
                    value={forgotForm.email}
                    onChange={setForgotField('email')}
                    placeholder="example@example.com"
                    autoComplete="email"
                    error={errors.email}
                  />
                </div>

                <button
                  type="submit"
                  disabled={busy}
                  className={cx(
                    'mt-5 inline-flex w-full items-center justify-center gap-2 rounded-2xl px-5 py-3.5 text-sm font-semibold transition',
                    busy ? 'cursor-not-allowed opacity-70' : '',
                    PRIMARY_BUTTON
                  )}
                >
                  <Mail size={16} />
                  {busy ? 'Preparing reset...' : 'Send reset link'}
                </button>

                <div className="mt-4 flex justify-center">
                  <button
                    type="button"
                    onClick={goToLogin}
                    className="text-[13px] font-semibold text-[#173324] underline underline-offset-2 transition hover:text-[#2D6A4F]"
                  >
                    Back to login
                  </button>
                </div>
              </form>
            ) : null}

            {/* =====================================================
                REGISTER
            ====================================================== */}
            {parsedMode.baseMode === 'register' ? (
              <form onSubmit={handleRegister} className="mt-5 space-y-4">
                <Stepper step={registerStep} />
                <RoleSwitch role={registerRole} onChange={setRegisterRole} />

                {registerStep === 1 ? (
                  <div className={cx('p-5 lg:p-6', PANEL_CARD)}>
                    <div className="text-[16px] font-bold text-[#173324]">Personal details</div>
                    <p className="mt-1.5 text-[13px] leading-6 text-[#5B7366]">
                      Start with the basic details only.
                    </p>

                    <div className="mt-5 grid gap-4 md:grid-cols-2">
                      <DialogField
                        label="Full name"
                        value={registerForm.fullName}
                        onChange={setRegisterField('fullName')}
                        placeholder="Firstname & Surname"
                        autoComplete="name"
                        error={errors.fullName}
                      />

                      <DialogField
                        label="Email address"
                        value={registerForm.email}
                        onChange={setRegisterField('email')}
                        placeholder="example@example.com"
                        autoComplete="email"
                        error={errors.email}
                      />

                      <DialogField
                        label="Phone number"
                        value={registerForm.phone}
                        onChange={setRegisterField('phone')}
                        placeholder="0812345678"
                        autoComplete="tel"
                        helperText="Use a number you actively use for account updates."
                        error={errors.phone}
                      />

                      <DialogField
                        label="Location"
                        value={registerForm.location}
                        onChange={setRegisterField('location')}
                        placeholder="Town or Region"
                        autoComplete="address-level2"
                        helperText="This helps connect buyers and sellers more effectively."
                        error={errors.location}
                      />
                    </div>
                  </div>
                ) : (
                  <div className={cx('p-5 lg:p-6', PANEL_CARD)}>
                    <div className="text-[16px] font-bold text-[#173324]">Account security</div>
                    <p className="mt-1.5 text-[13px] leading-6 text-[#5B7366]">
                      Create a strong password for your account.
                    </p>

                    <div className="mt-5 grid gap-4 md:grid-cols-2">
                      <DialogField
                        label="Password"
                        type="password"
                        value={registerForm.password}
                        onChange={setRegisterField('password')}
                        placeholder="Minimum 6 characters"
                        autoComplete="new-password"
                        showToggle
                        error={errors.password}
                      />

                      <DialogField
                        label="Confirm password"
                        type="password"
                        value={registerForm.confirmPassword}
                        onChange={setRegisterField('confirmPassword')}
                        placeholder="Re-enter your password"
                        autoComplete="new-password"
                        showToggle
                        error={errors.confirmPassword}
                      />
                    </div>
                  </div>
                )}

                <div className="grid gap-3 md:grid-cols-2">
                  <button
                    type="button"
                    onClick={registerStep === 1 ? goToLogin : () => setRegisterStep(1)}
                    className={cx(
                      'inline-flex items-center justify-center gap-2 rounded-2xl px-5 py-3.5 text-sm font-semibold transition',
                      SECONDARY_BUTTON
                    )}
                  >
                    <ArrowLeft size={16} />
                    {registerStep === 1 ? 'Back to login' : 'Back'}
                  </button>

                  {registerStep === 1 ? (
                    <button
                      type="button"
                      onClick={handleRegisterNext}
                      className={cx(
                        'inline-flex items-center justify-center gap-2 rounded-2xl px-5 py-3.5 text-sm font-semibold transition',
                        PRIMARY_BUTTON
                      )}
                    >
                      Continue
                      <ArrowRight size={16} />
                    </button>
                  ) : (
                    <button
                      type="submit"
                      disabled={busy}
                      className={cx(
                        'inline-flex items-center justify-center gap-2 rounded-2xl px-5 py-3.5 text-sm font-semibold transition',
                        busy ? 'cursor-not-allowed opacity-70' : '',
                        PRIMARY_BUTTON
                      )}
                    >
                      {busy ? 'Creating account...' : 'Create account'}
                      <ArrowRight size={16} />
                    </button>
                  )}
                </div>

                <div className="flex justify-center text-[13px] text-[#61796B]">
                  <span>Already registered?</span>
                  <button
                    type="button"
                    onClick={goToLogin}
                    className="ml-1 font-semibold text-[#173324] underline underline-offset-2 transition hover:text-[#2D6A4F]"
                  >
                    Login here
                  </button>
                </div>
              </form>
            ) : null}
          </div>
        </section>
      </div>
    </div>
  );
}
