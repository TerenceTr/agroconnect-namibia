// ============================================================================
// src/test/handlers.js
// ----------------------------------------------------------------------------
// ROLE:
// • MSW request handlers for tests
// ============================================================================

import { http, HttpResponse } from 'msw';

const API = process.env.REACT_APP_API_URL || '';

export const handlers = [
  http.post(`${API}/api/orders`, async ({ request }) => {
    const body = await request.json();
    return HttpResponse.json({
      id: 999,
      created_at: new Date().toISOString(),
      items: body.items,
      message: 'ok',
    });
  }),
];
