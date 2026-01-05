// ============================================================================
// frontend\src\components\customer\__tests__\CheckoutPanel.test.jsx
// ----------------------------------------------------------------------------
// ROLE:
// • Verifies checkout validation
// • Ensures order placement callback fires correctly
// ============================================================================

import React from 'react';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import CheckoutPanel from '../CheckoutPanel';

describe('CheckoutPanel', () => {
  const mockPlaceOrder = jest.fn();

  const baseProps = {
    cart: {
      items: [{ product_id: 1, qty: 2 }],
    },
    totals: {
      subtotal: 120,
    },
    onPlaceOrder: mockPlaceOrder,
  };

  beforeEach(() => {
    jest.clearAllMocks();
  });

  test('renders checkout form', () => {
    render(<CheckoutPanel {...baseProps} />);

    expect(screen.getByText(/checkout/i)).toBeInTheDocument();
    expect(screen.getByText(/place order/i)).toBeInTheDocument();
  });

  test('disables checkout when cart is empty', () => {
    render(
      <CheckoutPanel
        {...baseProps}
        cart={{ items: [] }}
        totals={{ subtotal: 0 }}
      />
    );

    expect(screen.getByText(/place order/i)).toBeDisabled();
  });

  test('submits order payload correctly', async () => {
    const user = userEvent.setup();

    render(<CheckoutPanel {...baseProps} />);

    await user.click(screen.getByText(/place order/i));

    expect(mockPlaceOrder).toHaveBeenCalledTimes(1);

    const payload = mockPlaceOrder.mock.calls[0][0];
    expect(payload.items).toEqual([{ product_id: 1, qty: 2 }]);
    expect(payload.payment_method).toBe('cash');
  });
});
