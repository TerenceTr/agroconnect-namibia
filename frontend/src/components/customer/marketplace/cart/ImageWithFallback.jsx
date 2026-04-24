// ============================================================================
// frontend/src/components/customer/marketplace/cart/ImageWithFallback.jsx
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Robust product thumbnail with multiple fallback candidates.
//   Uses resolveProductImageCandidates() to avoid broken images in cart.
// ============================================================================

import React, { useEffect, useMemo, useState } from "react";
import { resolveProductImageCandidates } from "../../../../utils/productImage";

export default function ImageWithFallback({ productLike, alt, className }) {
  const candidates = useMemo(
    () => resolveProductImageCandidates(productLike),
    [productLike]
  );
  const [idx, setIdx] = useState(0);

  useEffect(() => {
    setIdx(0);
  }, [productLike?.id, productLike?.name, productLike?.image_url]);

  const src = candidates[idx] || candidates[candidates.length - 1];

  return (
    <img
      src={src}
      alt={alt}
      className={className}
      loading="lazy"
      onError={() => setIdx((i) => Math.min(i + 1, candidates.length - 1))}
    />
  );
}
