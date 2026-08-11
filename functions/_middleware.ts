import type { PagesFunction } from '@cloudflare/workers-types';

export const onRequest: PagesFunction = async (context) => {
  const request = context.request;
  const next = context.next;
  const url = new URL(request.url);

  // Don't intercept function requests
  if (url.pathname.startsWith('/functions/')) {
    return next();
  }

  const response = await next();

  response.headers.set('Access-Control-Allow-Origin', '*');
  response.headers.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  response.headers.set('Access-Control-Allow-Headers', 'Content-Type');

  return response;
};
