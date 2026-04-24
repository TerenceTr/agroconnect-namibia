// ============================================================================
// frontend/src/pages/Register.js
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Legacy public register route wrapper.
//
// NOTE:
//   The real public registration UI now lives on StartScreen via AuthDialog.
//   Role hints from route state or ?role= are preserved.
// ============================================================================

import React from 'react';

import PublicAuthRouteRedirect from '../components/auth/PublicAuthRouteRedirect';

export default function Register() {
  return <PublicAuthRouteRedirect mode="register" fallbackRole="customer" />;
}
