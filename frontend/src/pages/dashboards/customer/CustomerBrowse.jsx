// pages/dashboards/customer/CustomerBrowse.jsx
// ============================================================================
// ROLE:
// • Browse & search products
// • Entry point for customer journey
// ============================================================================

import React, { useEffect, useState } from 'react';
import ProductBrowser from '../../../components/customer/ProductBrowser';
import ProductHighlights from '../../../components/customer/ProductHighlights';
import toast from 'react-hot-toast';
import {
  fetchProducts,
  fetchNewProducts,
  fetchTopSellingProducts,
} from '../../../services/customerApi';

export default function CustomerBrowse({ onSelect }) {
  const [products, setProducts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [newItems, setNewItems] = useState([]);
  const [topItems, setTopItems] = useState([]);

  useEffect(() => {
    (async () => {
      try {
        setLoading(true);
        setProducts(await fetchProducts());
        setNewItems(await fetchNewProducts(6));
        setTopItems(await fetchTopSellingProducts(6));
      } catch {
        toast.error('Failed to load products');
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  return (
    <>
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        <ProductHighlights title="New Products" items={newItems} onPick={onSelect} />
        <ProductHighlights title="Top Selling" items={topItems} onPick={onSelect} />
      </div>

      <ProductBrowser products={products} loading={loading} onSelect={onSelect} />
    </>
  );
}
