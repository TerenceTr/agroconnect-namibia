// ============================================================================
// frontend/src/pages/Login.js
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Legacy public login route wrapper.
//
// NOTE:
//   The real public auth UI now lives on StartScreen via AuthDialog.
// ============================================================================

import React from 'react';

import PublicAuthRouteRedirect from '../components/auth/PublicAuthRouteRedirect';

export default function Login() {
  return <PublicAuthRouteRedirect mode="login" />;
}
