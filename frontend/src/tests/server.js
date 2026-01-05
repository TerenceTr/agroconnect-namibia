// ============================================================================
// src/test/server.js
// ----------------------------------------------------------------------------
// ROLE:
// • MSW server lifecycle for Jest
// ============================================================================

import { setupServer } from 'msw/node';
import { handlers } from './handlers';

export const server = setupServer(...handlers);
