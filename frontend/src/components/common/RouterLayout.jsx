// ============================================================================
// src/components/common/RouterLayout.jsx — AgroConnect Namibia
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Route-shell component that wraps groups of routes.
//   MUST render <Outlet /> so nested routes can appear.
//
// RESPONSIBILITIES:
//   • Safe, local route transitions for dashboard pages.
//   • DEV route logging.
//   • Optional route audit events (disabled by default).
//
// IMPORTANT BUG FIX:
//   Axios baseURL already ends with "/api".
//   So audit endpoint must be "/audit/route" NOT "/api/audit/route".
//
// ALSO IMPORTANT:
//   Your backend currently DOES NOT implement "/api/audit/route",
//   so audit is OFF by default to prevent CORS/404 noise.
// ============================================================================

import React, { useEffect, useMemo, useRef } from 'react';
import { Outlet, useLocation } from 'react-router-dom';
import { CSSTransition, SwitchTransition } from 'react-transition-group';

import './dashboard-transitions.css';
import api from '../../api';

export default function RouterLayout() {
  const location = useLocation();
  const nodeRef = useRef(null);

  // ---------------------------------------------------------------------------
  // Respect reduced motion settings (accessibility)
  // ---------------------------------------------------------------------------
  const reduceMotion = useMemo(() => {
    try {
      return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    } catch {
      return false;
    }
  }, []);

  // ---------------------------------------------------------------------------
  // DEV route debugging
  // ---------------------------------------------------------------------------
  useEffect(() => {
    if (process.env.NODE_ENV === 'development') {
      // eslint-disable-next-line no-console
      console.debug('[ROUTE]', location.pathname);
    }
  }, [location.pathname]);

  // ---------------------------------------------------------------------------
  // OPTIONAL route audit logging (OFF by default)
  // Enable by setting: REACT_APP_ENABLE_ROUTE_AUDIT=true
  // ---------------------------------------------------------------------------
  useEffect(() => {
    const enabled = process.env.REACT_APP_ENABLE_ROUTE_AUDIT === 'true';
    if (!enabled) return;

    // IMPORTANT: do NOT prefix "/api" here (Axios already has it).
    api
      .post('/audit/route', {
        path: location.pathname,
        ts: new Date().toISOString(),
      })
      .catch(() => {
        /* silent fail */
      });
  }, [location.pathname]);

  // If reduced motion is preferred, skip transitions entirely.
  if (reduceMotion) {
    return <Outlet />;
  }

  return (
    <SwitchTransition mode="out-in">
      <CSSTransition
        key={location.pathname}
        classNames="dash-animate"
        timeout={400}
        unmountOnExit
        nodeRef={nodeRef}
      >
        <div ref={nodeRef} className="dash-transition-wrapper">
          <Outlet />
        </div>
      </CSSTransition>
    </SwitchTransition>
  );
}
