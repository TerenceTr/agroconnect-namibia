// ====================================================================
// frontend\src\components\common\DashboardTransition.jsx
// 🌾 DashboardTransition — Enhanced Route Animation Wrapper
// --------------------------------------------------------------------
// Adds smooth transitions when switching between dashboards.
// Supports: slide, fade, depth, and combined animations.
// ====================================================================

import React from "react";
import { CSSTransition, SwitchTransition } from "react-transition-group";
import "./dashboard-transitions.css";

export default function DashboardTransition({ children, routeKey }) {
  return (
    <SwitchTransition>
      <CSSTransition
        key={routeKey}
        timeout={450}
        classNames="dash-animate"
        appear
      >
        <div className="dash-transition-wrapper">{children}</div>
      </CSSTransition>
    </SwitchTransition>
  );
}
