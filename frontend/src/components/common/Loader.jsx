// ====================================================================
//  frontend\src\components\common\Loader.jsx 
//🌾 AgroConnect Namibia — Premium Loader Animation
// --------------------------------------------------------------------
// A centered animated loader with pulsing ring + shimmering logo text.
// Fades out smoothly when parent adds `.fade-out`.
// ====================================================================

import React from "react";
import "./loader.css";

export default function Loader() {
  return (
    <div className="ac-loader-container fade-in">
      <div className="ac-loader-ring"></div>

      <div className="ac-loader-text">
        <span>A</span><span>g</span><span>r</span><span>o</span>
        <span>C</span><span>o</span><span>n</span><span>n</span>
        <span>e</span><span>c</span><span>t</span>
      </div>
    </div>
  );
}
