// ============================================================================
// frontend/src/pages/ForgotPassword.js
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Legacy forgot-password route wrapper.
//
// NOTE:
//   The real password-reset request UI now lives on StartScreen via AuthDialog.
// ============================================================================

import React from 'react';

import PublicAuthRouteRedirect from '../components/auth/PublicAuthRouteRedirect';

export default function ForgotPassword() {
  return <PublicAuthRouteRedirect mode="forgot" />;
}
