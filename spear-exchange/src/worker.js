import bcrypt from 'bcryptjs';
export { ChatRoom } from './chat-room.js';

const DEFAULT_WORKER_URL = 'https://spear-exchange.lenny-paz123.workers.dev';
const DEFAULT_FRONTEND_URL = 'https://lennypaz.github.io/SpearExchange';
const DEFAULT_ALLOWED_ORIGINS = [
  'http://localhost:3000',
  'http://127.0.0.1:3000',
  'http://localhost:8000',
  'http://127.0.0.1:8000'
];
const LISTING_TYPE_GOODS = 'goods';
const LISTING_TYPE_SUBLEASE = 'sublease';
const PRICE_PERIOD_ONE_TIME = 'one_time';
const PRICE_PERIOD_MONTHLY = 'monthly';
const CATEGORY_3D_PRINTS = '3d-printed-fsu-items';
const CATEGORY_SUBLEASE = 'sublease';

function trimTrailingSlash(value) {
  return value ? value.replace(/\/+$/, '') : value;
}

function getWorkerBaseUrl(env) {
  return trimTrailingSlash(env.PRODUCTION_URL || DEFAULT_WORKER_URL);
}

function getFrontendBaseUrl(env) {
  return trimTrailingSlash(env.FRONTEND_URL || DEFAULT_FRONTEND_URL);
}

function getFrontendOrigin(env) {
  return new URL(getFrontendBaseUrl(env)).origin;
}

function getAllowedOrigins(env) {
  const origins = new Set(DEFAULT_ALLOWED_ORIGINS);
  origins.add(getFrontendOrigin(env));

  if (env.ALLOWED_ORIGINS) {
    for (const origin of env.ALLOWED_ORIGINS.split(',').map(item => item.trim()).filter(Boolean)) {
      origins.add(origin);
    }
  }

  return origins;
}

function getCorsHeaders(request, env) {
  const requestOrigin = request.headers.get('Origin');
  const allowedOrigins = getAllowedOrigins(env);
  const allowOrigin = requestOrigin && allowedOrigins.has(requestOrigin)
    ? requestOrigin
    : getFrontendOrigin(env);

  return {
    'Access-Control-Allow-Origin': allowOrigin,
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, Cookie',
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Expose-Headers': 'Set-Cookie',
    'Vary': 'Origin'
  };
}

function buildFrontendRedirect(env, path, params = {}) {
  const redirectUrl = new URL(`${getFrontendBaseUrl(env)}${path}`);

  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== '') {
      redirectUrl.searchParams.set(key, String(value));
    }
  });

  return new Response(
    `<!DOCTYPE html><html><head><meta http-equiv="refresh" content="0;url=${redirectUrl.toString()}"></head></html>`,
    { headers: { 'Content-Type': 'text/html' } }
  );
}

function parseBooleanFlag(value, defaultValue = false) {
  if (value === undefined || value === null || value === '') {
    return defaultValue;
  }

  if (typeof value === 'boolean') {
    return value;
  }

  if (typeof value === 'number') {
    return value !== 0;
  }

  const normalized = String(value).trim().toLowerCase();
  return ['1', 'true', 'yes', 'on'].includes(normalized);
}

function parseNullableNumber(value) {
  if (value === undefined || value === null || value === '') {
    return null;
  }

  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function normalizeListingType(value) {
  return value === LISTING_TYPE_SUBLEASE ? LISTING_TYPE_SUBLEASE : LISTING_TYPE_GOODS;
}

function isValidListingType(value) {
  return value === LISTING_TYPE_GOODS || value === LISTING_TYPE_SUBLEASE;
}

function normalizePricePeriod(value, listingType) {
  if (listingType === LISTING_TYPE_SUBLEASE) {
    return PRICE_PERIOD_MONTHLY;
  }

  return value === PRICE_PERIOD_MONTHLY ? PRICE_PERIOD_MONTHLY : PRICE_PERIOD_ONE_TIME;
}

function isValidPricePeriod(value) {
  return value === PRICE_PERIOD_ONE_TIME || value === PRICE_PERIOD_MONTHLY;
}

function normalizeCategory(value, listingType) {
  if (listingType === LISTING_TYPE_SUBLEASE) {
    return CATEGORY_SUBLEASE;
  }

  return String(value || '').trim().toLowerCase();
}

function serializeImageUrls(imageUrls) {
  if (Array.isArray(imageUrls)) {
    return JSON.stringify(imageUrls);
  }

  if (typeof imageUrls === 'string' && imageUrls.trim()) {
    return imageUrls;
  }

  return JSON.stringify([]);
}

function parseImageUrls(value) {
  if (!value) {
    return [];
  }

  if (Array.isArray(value)) {
    return value;
  }

  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function formatListingRecord(record) {
  if (!record) {
    return record;
  }

  return {
    ...record,
    image_urls: parseImageUrls(record.image_urls),
    listing_type: record.listing_type || LISTING_TYPE_GOODS,
    price_period: record.price_period || PRICE_PERIOD_ONE_TIME,
    negotiable: Boolean(record.negotiable),
    furnished: Boolean(record.furnished),
    utilities_included: Boolean(record.utilities_included),
    parking_available: Boolean(record.parking_available),
    pet_friendly: Boolean(record.pet_friendly),
    roommates_allowed: Boolean(record.roommates_allowed)
  };
}

function buildListingPayload(body, options = {}) {
  const partial = options.partial === true;
  const rawListingType = body.listing_type;
  if (rawListingType !== undefined && rawListingType !== null && rawListingType !== '' && !isValidListingType(rawListingType)) {
    return { error: 'Invalid listing_type. Expected goods or sublease.' };
  }

  const listingType = normalizeListingType(body.listing_type);
  if (
    body.price_period !== undefined &&
    body.price_period !== null &&
    body.price_period !== '' &&
    !isValidPricePeriod(body.price_period)
  ) {
    return { error: 'Invalid price_period. Expected one_time or monthly.' };
  }

  const pricePeriod = normalizePricePeriod(body.price_period, listingType);
  const category = normalizeCategory(body.category, listingType);

  const payload = {
    title: body.title?.trim() || '',
    description: body.description?.trim() || '',
    price: parseNullableNumber(body.price),
    category,
    condition: listingType === LISTING_TYPE_SUBLEASE ? 'n/a' : (body.condition?.trim() || ''),
    listing_type: listingType,
    price_period: pricePeriod,
    negotiable: parseBooleanFlag(body.negotiable),
    contact_method: body.contact_method?.trim() || '',
    phone_number: body.phone_number?.trim() || '',
    image_urls: serializeImageUrls(body.imageUrls ?? body.image_urls),
    location: body.location?.trim() || '',
    availability_start: body.availability_start || null,
    availability_end: body.availability_end || null,
    housing_type: listingType === LISTING_TYPE_SUBLEASE ? (body.housing_type?.trim() || '') : null,
    bedrooms: listingType === LISTING_TYPE_SUBLEASE ? parseNullableNumber(body.bedrooms) : null,
    bathrooms: listingType === LISTING_TYPE_SUBLEASE ? parseNullableNumber(body.bathrooms) : null,
    furnished: listingType === LISTING_TYPE_SUBLEASE ? parseBooleanFlag(body.furnished) : false,
    utilities_included: listingType === LISTING_TYPE_SUBLEASE ? parseBooleanFlag(body.utilities_included) : false,
    parking_available: listingType === LISTING_TYPE_SUBLEASE ? parseBooleanFlag(body.parking_available) : false,
    pet_friendly: listingType === LISTING_TYPE_SUBLEASE ? parseBooleanFlag(body.pet_friendly) : false,
    roommates_allowed: listingType === LISTING_TYPE_SUBLEASE ? parseBooleanFlag(body.roommates_allowed, true) : false,
    lease_transfer_fee: listingType === LISTING_TYPE_SUBLEASE ? parseNullableNumber(body.lease_transfer_fee) : null,
    address_text: listingType === LISTING_TYPE_SUBLEASE ? (body.address_text?.trim() || '') : null,
    sublease_notes: listingType === LISTING_TYPE_SUBLEASE ? (body.sublease_notes?.trim() || '') : null
  };

  if (!partial) {
    const missingFields = [];

    if (!payload.title) missingFields.push('title');
    if (!payload.description) missingFields.push('description');
    if (payload.price === null) missingFields.push('price');
    if (!payload.category) missingFields.push('category');
    if (!payload.contact_method) missingFields.push('contact_method');

    if (payload.listing_type === LISTING_TYPE_GOODS && !payload.condition) {
      missingFields.push('condition');
    }

    if (payload.listing_type === LISTING_TYPE_SUBLEASE) {
      if (!payload.availability_start) missingFields.push('availability_start');
      if (!payload.availability_end) missingFields.push('availability_end');
      if (!payload.housing_type) missingFields.push('housing_type');
      if (!payload.address_text) missingFields.push('address_text');
    }

    if (missingFields.length) {
      return { error: `Missing required fields: ${missingFields.join(', ')}` };
    }
  }

  if (payload.price !== null && payload.price < 0) {
    return { error: 'Price must be zero or greater' };
  }

  if (
    payload.listing_type === LISTING_TYPE_SUBLEASE &&
    payload.availability_start &&
    payload.availability_end &&
    new Date(payload.availability_start) > new Date(payload.availability_end)
  ) {
    return { error: 'Availability end must be after availability start' };
  }

  return { payload };
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    
    // Handle API routes
    if (url.pathname.startsWith('/api/')) {
      return handleAPI(request, env, url);
    }
	
	// Handle password reset verification 
    if (url.pathname === '/verify-reset') {
      return handleVerifyResetToken(request, env, url);
    }
	
    // Handle email verification
    if (url.pathname === '/verify') {
      return handleEmailVerification(request, env, url);
    }
    
    // Default response for non-API routes
    return new Response(JSON.stringify({ 
      message: 'Spear Exchange API',
      version: '1.0',
      endpoints: [
        'POST /api/signup',
        'POST /api/login', 
        'GET /api/me',
        'POST /api/resend-verification',
        'GET /verify?token=xxx',
		'GET /verify-reset?token=xxx',
        'POST /api/upload-image',
        'GET /api/listings',
        'POST /api/listings',
        'GET /api/listings/:id',
        'PUT /api/listings/:id',
        'DELETE /api/listings/:id',
        'GET /api/conversations',
        'GET /api/conversations/:id/messages',
        'POST /api/conversations/:id/messages',
        'PUT /api/conversations/:id/read',
        'POST /api/favorites/:id',
        'DELETE /api/favorites/:id',
        'GET /api/users/:id/listings',
		'POST /api/forgot-password',
        'POST /api/reset-password' 
      ]
    }), {
      headers: { 'Content-Type': 'application/json' }
    });
  },
};

async function handleAPI(request, env, url) {
  const corsHeaders = getCorsHeaders(request, env);

  if (request.method === 'OPTIONS') {
    return new Response(null, { 
      headers: corsHeaders,
      status: 204
    });
  }

  try {
    // Test database connection
    if (url.pathname === '/api/test' && request.method === 'GET') {
      const result = await env.DB.prepare('SELECT 1 as test').first();
      return new Response(JSON.stringify({ 
        message: 'Database connected!', 
        test: result,
        timestamp: new Date().toISOString()
      }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }

    // Authentication endpoints
    if (url.pathname === '/api/signup' && request.method === 'POST') {
      return handleSignup(request, env, corsHeaders);
    }

    if (url.pathname === '/api/login' && request.method === 'POST') {
      return handleLogin(request, env, corsHeaders);
    }

    if (url.pathname === '/api/me' && request.method === 'GET') {
      return handleCheckAuth(request, env, corsHeaders);
    }

    if (url.pathname === '/api/resend-verification' && request.method === 'POST') {
      return handleResendVerification(request, env, corsHeaders);
    }

    if (url.pathname === '/api/logout' && request.method === 'POST') {
      return handleLogout(request, env, corsHeaders);
    }

    // Image upload endpoint
    if (url.pathname === '/api/upload-image' && request.method === 'POST') {
      return handleImageUpload(request, env, corsHeaders);
    }

    // Listings endpoints
    if (url.pathname === '/api/listings' && request.method === 'GET') {
      return handleGetListings(request, env, corsHeaders);
    }

    if (url.pathname === '/api/listings' && request.method === 'POST') {
      return handleCreateListing(request, env, corsHeaders);
    }

    if (url.pathname.match(/^\/api\/listings\/\d+$/) && request.method === 'GET') {
      const listingId = url.pathname.split('/')[3];
      return handleGetListing(listingId, env, corsHeaders);
    }

    if (url.pathname.match(/^\/api\/listings\/\d+$/) && request.method === 'PUT') {
      const listingId = url.pathname.split('/')[3];
      return handleUpdateListing(listingId, request, env, corsHeaders);
    }

    if (url.pathname.match(/^\/api\/listings\/\d+$/) && request.method === 'DELETE') {
      const listingId = url.pathname.split('/')[3];
      return handleDeleteListing(listingId, request, env, corsHeaders);
    }

    // Conversations endpoints (Phase 2 - Full Messages Page)
    if (url.pathname === '/api/conversations' && request.method === 'GET') {
      return handleGetConversations(request, env, corsHeaders);
    }

    if (url.pathname.match(/^\/api\/conversations\/\d+\/messages$/) && request.method === 'GET') {
      const conversationId = url.pathname.split('/')[3];
      return handleGetConversationMessages(conversationId, request, env, corsHeaders);
    }

    if (url.pathname.match(/^\/api\/conversations\/\d+\/messages$/) && request.method === 'POST') {
      const conversationId = url.pathname.split('/')[3];
      return handleSendConversationMessage(conversationId, request, env, corsHeaders);
    }

    if (url.pathname.match(/^\/api\/conversations\/\d+\/read$/) && request.method === 'PUT') {
      const conversationId = url.pathname.split('/')[3];
      return handleMarkMessagesAsRead(conversationId, request, env, corsHeaders);
    }

    // Messages endpoints (Phase 1)
    if (url.pathname === '/api/messages' && request.method === 'POST') {
      return handleSendMessage(request, env, corsHeaders);
    }

    if (url.pathname.match(/^\/api\/listings\/\d+\/messages$/) && request.method === 'GET') {
      const listingId = url.pathname.split('/')[3];
      return handleGetListingMessages(listingId, request, env, corsHeaders);
    }

    // Favorites endpoints
    if (url.pathname.match(/^\/api\/favorites\/\d+$/) && request.method === 'POST') {
      const listingId = url.pathname.split('/')[3];
      return handleAddFavorite(listingId, request, env, corsHeaders);
    }

    if (url.pathname.match(/^\/api\/favorites\/\d+$/) && request.method === 'DELETE') {
      const listingId = url.pathname.split('/')[3];
      return handleRemoveFavorite(listingId, request, env, corsHeaders);
    }

    if (url.pathname === '/api/favorites' && request.method === 'GET') {
      return handleGetFavorites(request, env, corsHeaders);
    }

    // User profile endpoints
    if (url.pathname.match(/^\/api\/users\/\d+$/) && request.method === 'GET') {
      const userId = url.pathname.split('/')[3];
      return handleGetUserProfile(userId, env, corsHeaders);
    }

    // User listings endpoint
    if (url.pathname.match(/^\/api\/users\/\d+\/listings$/) && request.method === 'GET') {
      const userId = url.pathname.split('/')[3];
      return handleGetUserListings(userId, env, corsHeaders);
    }

    // WebSocket connection endpoint
    if (url.pathname === '/api/chat/connect' && request.headers.get('Upgrade') === 'websocket') {
      return handleWebSocketConnection(request, env);
    }

    // Get active users in a conversation
    if (url.pathname.match(/^\/api\/conversations\/\d+\/users$/) && request.method === 'GET') {
      const conversationId = url.pathname.split('/')[3];
      return handleGetActiveUsers(conversationId, env, corsHeaders);
    }
    
    // Enhanced message endpoints for real-time features
    if (url.pathname.match(/^\/api\/conversations\/\d+\/typing$/) && request.method === 'POST') {
      const conversationId = url.pathname.split('/')[3];
      return handleTypingIndicator(conversationId, request, env, corsHeaders);
    }
    
    // Get unread message counts
    if (url.pathname === '/api/conversations/unread' && request.method === 'GET') {
      return handleGetUnreadCounts(request, env, corsHeaders);
    }
    
    // Mark specific message as read (for read receipts)
    if (url.pathname.match(/^\/api\/messages\/\d+\/read$/) && request.method === 'PUT') {
      const messageId = url.pathname.split('/')[3];
      return handleMarkMessageRead(messageId, request, env, corsHeaders);
    }
	
	// Forgot password endpoints
    if (url.pathname === '/api/forgot-password' && request.method === 'POST') {
      return handleForgotPassword(request, env, corsHeaders);
    }

    if (url.pathname === '/api/reset-password' && request.method === 'POST') {
      return handleResetPassword(request, env, corsHeaders);
    }
	
    return new Response(JSON.stringify({ error: 'Route not found' }), {
      status: 404,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error('API Error:', error);
    return new Response(JSON.stringify({ 
      error: 'Internal server error',
      details: error.message 
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

// Helper function to get user from session (supports both cookies and Authorization header)
async function getUserFromSession(request, env) {
  let sessionToken = null;
  
  // First try Authorization header (for mobile compatibility)
  const authHeader = request.headers.get('Authorization');
  if (authHeader && authHeader.startsWith('Bearer ')) {
    sessionToken = authHeader.substring(7);
  }
  
  // Fall back to cookie if no Authorization header
  if (!sessionToken) {
    const cookieHeader = request.headers.get('Cookie');
    if (cookieHeader) {
      sessionToken = cookieHeader
        .split(';')
        .find(cookie => cookie.trim().startsWith('session='))
        ?.split('=')[1];
    }
  }
  
  if (!sessionToken) return null;
  
  const session = await env.DB.prepare(
    'SELECT s.user_id, u.email, u.profile_name FROM user_sessions s JOIN users u ON s.user_id = u.id WHERE s.session_token = ? AND s.expires_at > datetime("now")'
  ).bind(sessionToken).first();
  
  return session;
}

// Authentication functions
async function verifyCaptcha(token, env) {
  try {
    if (!env.TURNSTILE_SECRET_KEY) {
      console.error('TURNSTILE_SECRET_KEY is not configured');
      return false;
    }

    const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `secret=${env.TURNSTILE_SECRET_KEY}&response=${token}`
    });
    const result = await response.json();
    return result.success;
  } catch (error) {
    console.error('CAPTCHA verification error:', error);
    return false;
  }
}

async function sendVerificationEmail(email, token, env) {
  try {
    if (!env.RESEND_API_KEY) {
      console.error('RESEND_API_KEY is not configured');
      return false;
    }

    const baseUrl = getWorkerBaseUrl(env);
    const verificationUrl = `${baseUrl}/verify?token=${token}`;
    
    const emailHtml = `
      <!DOCTYPE html>
      <html>
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
        </head>
        <body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f9f9f9;">
          
          <table width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color: #f9f9f9;">
            <tr>
              <td align="center" style="padding: 40px 20px;">
                <table width="100%" style="max-width: 600px;" cellpadding="0" cellspacing="0" border="0">
                  
                  <!-- Header with rounded top corners -->
                  <tr>
                    <td style="background: linear-gradient(135deg, #8B2635, #6B1B2A); background-color: #8B2635; padding: 40px 30px; text-align: center; border-radius: 12px 12px 0 0;">
                      <div style="display: inline-block; width: 60px; height: 60px; background-color: rgba(255, 255, 255, 0.15); border-radius: 12px; border: 2px solid rgba(255, 255, 255, 0.2); color: white; font-weight: bold; font-size: 24px; line-height: 56px; text-align: center; margin-bottom: 15px;">SE</div>
                      <h1 style="margin: 0; font-size: 28px; font-weight: bold; color: white;">Welcome to The Spear Exchange!</h1>
                    </td>
                  </tr>
                  
                  <!-- Content with rounded bottom corners -->
                  <tr>
                    <td style="background-color: #ffffff; padding: 40px 30px; border-radius: 0 0 12px 12px;">
                      
                      <h2 style="color: #2C3E50; font-size: 24px; margin: 0 0 20px 0; font-weight: 600;">Verify Your FSU Email</h2>
                      
                      <p style="color: #5A6C7D; margin: 0 0 15px 0; font-size: 16px; line-height: 1.6;">Hi there!</p>
                      
                      <p style="color: #5A6C7D; margin: 0 0 25px 0; font-size: 16px; line-height: 1.6;">Welcome to The Spear Exchange, the trusted marketplace for FSU students! To complete your account setup, please verify your FSU email address by clicking the button below:</p>
                      
                      <!-- Button -->
                      <div style="text-align: center; margin: 25px 0;">
                        <a href="${verificationUrl}" style="display: inline-block; background: linear-gradient(135deg, #8B2635, #6B1B2A); background-color: #8B2635; color: white; padding: 15px 30px; text-decoration: none; border-radius: 8px; font-weight: 600; font-size: 16px;">Verify My Email</a>
                      </div>
                      
                      <p style="color: #5A6C7D; margin: 20px 0 10px 0; font-size: 16px;">Or copy and paste this link into your browser:</p>
                      
                      <div style="background-color: #f0f0f0; padding: 15px; border-radius: 8px; margin: 15px 0; word-break: break-all; font-family: monospace; font-size: 14px; color: #8B2635; border: 1px solid #e0e0e0;">${verificationUrl}</div>
                      
                      <p style="color: #5A6C7D; margin: 20px 0; font-size: 16px; font-weight: 600;">This link expires in 24 hours.</p>
                      
                      <!-- Footer -->
                      <div style="border-top: 1px solid #e2e8f0; padding-top: 25px; margin-top: 30px; color: #9CA3AF; font-size: 14px;">
                        <p style="margin: 0 0 8px 0;"><strong style="color: #5A6C7D;">Go Noles! 🏈</strong></p>
                        <p style="margin: 0 0 15px 0;">The Spear Exchange Team</p>
                        <p style="margin: 0;"><em>This email was sent to ${email}. If you didn't create an account, you can safely ignore this email.</em></p>
                      </div>
                      
                    </td>
                  </tr>
                </table>
              </td>
            </tr>
          </table>
          
        </body>
      </html>
    `;

    const response = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${env.RESEND_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: 'The Spear Exchange <noreply@lennypaz.com>',
        to: email,
        subject: 'Verify your email address - The Spear Exchange',
        html: emailHtml,
      }),
    });

    if (!response.ok) {
      const errorData = await response.json();
      console.error('Email sending failed:', errorData);
      return false;
    }

    const result = await response.json();
    console.log('Email sent successfully:', result.id);
    return true;
  } catch (error) {
    console.error('Email sending error:', error);
    return false;
  }
}

async function handleSignup(request, env, corsHeaders) {
  try {
    const { email, password, phone, name, captchaToken } = await request.json();
    
    if (!email || !password || !phone || !name || !captchaToken) {
      return new Response(JSON.stringify({ error: 'All fields including CAPTCHA are required' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    const isCaptchaValid = await verifyCaptcha(captchaToken, env);
    if (!isCaptchaValid) {
      return new Response(JSON.stringify({ error: 'CAPTCHA verification failed. Please try again.' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    // To this:
	if (!email.endsWith('@fsu.edu') && !email.endsWith('@gmail.com')) {
	  return new Response(JSON.stringify({ error: 'Must use FSU email or Gmail for testing' }), {
		status: 400,
		headers: { ...corsHeaders, 'Content-Type': 'application/json' }
	  });
	}
    
    const existingUser = await env.DB.prepare(
      'SELECT email FROM users WHERE email = ?'
    ).bind(email).first();
    
    if (existingUser) {
      return new Response(JSON.stringify({ error: 'User already exists with this email' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const verificationToken = crypto.randomUUID();
    
    const result = await env.DB.prepare(
      'INSERT INTO users (email, password_hash, phone_number, profile_name, verification_token, is_verified) VALUES (?, ?, ?, ?, ?, ?)'
    ).bind(email, hashedPassword, phone, name, verificationToken, 0).run();
    
    const emailSent = await sendVerificationEmail(email, verificationToken, env);
    
    if (!emailSent) {
      return new Response(JSON.stringify({ 
        error: 'Account created but failed to send verification email. Please try again.' 
      }), {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    return new Response(JSON.stringify({ 
      message: 'Account created successfully! Please check your FSU email and click the verification link to complete your registration.',
      userId: result.meta.last_row_id,
      requiresVerification: true
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    console.error('Signup error:', error);
    return new Response(JSON.stringify({ 
      error: 'Failed to create account',
      details: error.message 
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

async function handleEmailVerification(request, env, url) {
  try {
    const token = url.searchParams.get('token');
    
    if (!token) {
      return buildFrontendRedirect(env, '/verify/', {
        status: 'invalid',
        message: 'Missing verification token'
      });
    }
    
    const user = await env.DB.prepare(
      'SELECT id, email, is_verified FROM users WHERE verification_token = ?'
    ).bind(token).first();
    
    if (!user) {
      return buildFrontendRedirect(env, '/verify/', {
        status: 'expired',
        message: 'This verification link is invalid or has expired'
      });
    }
    
    if (user.is_verified) {
      return buildFrontendRedirect(env, '/verify/', {
        status: 'already_verified',
        message: 'Your email is already verified'
      });
    }
    
    await env.DB.prepare(
      'UPDATE users SET is_verified = 1, verification_token = NULL WHERE id = ?'
    ).bind(user.id).run();
    
    return buildFrontendRedirect(env, '/verify/', {
      status: 'success',
      message: 'Your email has been verified successfully!'
    });
    
  } catch (error) {
    console.error('Email verification error:', error);
    return buildFrontendRedirect(env, '/verify/', {
      status: 'error',
      message: 'An error occurred during verification'
    });
  }
}

async function handleLogin(request, env, corsHeaders) {
  try {
    const { email, password } = await request.json();
    
    if (!email || !password) {
      return new Response(JSON.stringify({ error: 'Email and password are required' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    const user = await env.DB.prepare(
      'SELECT id, email, password_hash, profile_name, is_verified FROM users WHERE email = ?'
    ).bind(email).first();
    
    if (!user) {
      return new Response(JSON.stringify({ error: 'Invalid email or password' }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    const isValidPassword = await bcrypt.compare(password, user.password_hash);
    if (!isValidPassword) {
      return new Response(JSON.stringify({ error: 'Invalid email or password' }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    if (!user.is_verified) {
      return new Response(JSON.stringify({ 
        error: 'Please verify your email before logging in. Check your FSU email for the verification link.',
        requiresVerification: true 
      }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    const sessionToken = crypto.randomUUID();
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    
    await env.DB.prepare(
      'INSERT INTO user_sessions (user_id, session_token, expires_at) VALUES (?, ?, ?)'
    ).bind(user.id, sessionToken, expiresAt.toISOString()).run();
    
    const response = new Response(JSON.stringify({ 
      message: 'Login successful',
      user: { 
        id: user.id, 
        email: user.email, 
        name: user.profile_name 
      },
      sessionToken: sessionToken // Return token for mobile
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
    
    response.headers.set('Set-Cookie', 
      `session=${sessionToken}; HttpOnly; Secure; SameSite=None; Max-Age=${7 * 24 * 60 * 60}; Path=/`
    );
    
    return response;
    
  } catch (error) {
    console.error('Login error:', error);
    return new Response(JSON.stringify({ 
      error: 'Login failed',
      details: error.message 
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

async function handleCheckAuth(request, env, corsHeaders) {
  try {
    const user = await getUserFromSession(request, env);
    
    if (!user) {
      return new Response(JSON.stringify({ error: 'Not authenticated' }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    return new Response(JSON.stringify({ 
      user: {
        id: user.user_id,
        email: user.email,
        name: user.profile_name
      }
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    console.error('Auth check error:', error);
    return new Response(JSON.stringify({ 
      error: 'Authentication check failed' 
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

async function handleResendVerification(request, env, corsHeaders) {
  try {
    const { email } = await request.json();
    
    if (!email) {
      return new Response(JSON.stringify({ error: 'Email is required' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    const user = await env.DB.prepare(
      'SELECT id, email, is_verified, verification_token FROM users WHERE email = ?'
    ).bind(email).first();
    
    if (!user) {
      return new Response(JSON.stringify({ error: 'User not found' }), {
        status: 404,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    if (user.is_verified) {
      return new Response(JSON.stringify({ error: 'Email is already verified' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    let verificationToken = user.verification_token;
    if (!verificationToken) {
      verificationToken = crypto.randomUUID();
      await env.DB.prepare(
        'UPDATE users SET verification_token = ? WHERE id = ?'
      ).bind(verificationToken, user.id).run();
    }
    
    const emailSent = await sendVerificationEmail(email, verificationToken, env);
    
    if (!emailSent) {
      return new Response(JSON.stringify({ 
        error: 'Failed to send verification email. Please try again.' 
      }), {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    return new Response(JSON.stringify({ 
      message: 'Verification email sent! Please check your FSU email.' 
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    console.error('Resend verification error:', error);
    return new Response(JSON.stringify({ 
      error: 'Failed to resend verification email',
      details: error.message 
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

async function handleLogout(request, env, corsHeaders) {
  try {
    const user = await getUserFromSession(request, env);
    
    if (user) {
      const cookieHeader = request.headers.get('Cookie');
      const sessionToken = cookieHeader
        ?.split(';')
        ?.find(cookie => cookie.trim().startsWith('session='))
        ?.split('=')[1];
      
      if (sessionToken) {
        await env.DB.prepare(
          'DELETE FROM user_sessions WHERE session_token = ?'
        ).bind(sessionToken).run();
      }
    }
    
    const response = new Response(JSON.stringify({ message: 'Logged out successfully' }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
    
    response.headers.set('Set-Cookie', 
      'session=; HttpOnly; Secure; SameSite=None; Max-Age=0; Path=/'
    );
    
    return response;
    
  } catch (error) {
    console.error('Logout error:', error);
    return new Response(JSON.stringify({ 
      error: 'Logout failed' 
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

// Listings functions
async function handleGetListings(request, env, corsHeaders) {
  try {
    const url = new URL(request.url);
    const category = url.searchParams.get('category')?.trim().toLowerCase();
    const search = url.searchParams.get('search')?.trim();
    const rawListingType = url.searchParams.get('listing_type')?.trim();
    const hasListingTypeFilter = url.searchParams.has('listing_type');
    const listingType = rawListingType ? rawListingType.toLowerCase() : null;
    const limit = parseInt(url.searchParams.get('limit')) || 20;
    const offset = parseInt(url.searchParams.get('offset')) || 0;

    if (hasListingTypeFilter && !isValidListingType(listingType)) {
      return new Response(JSON.stringify({
        error: 'Invalid listing_type filter. Expected goods or sublease.'
      }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }

    let query = `
      SELECT l.*, u.profile_name as seller_name, u.email as seller_email
      FROM listings l
      JOIN users u ON l.user_id = u.id
      WHERE l.status = 'active'
    `;
    const params = [];

    if (category) {
      query += ' AND l.category = ?';
      params.push(category);
    }

    if (hasListingTypeFilter) {
      query += ' AND l.listing_type = ?';
      params.push(listingType);
    }

    if (search) {
      query += ' AND (l.title LIKE ? OR l.description LIKE ? OR l.location LIKE ? OR l.address_text LIKE ? OR l.sublease_notes LIKE ?)';
      params.push(`%${search}%`, `%${search}%`, `%${search}%`, `%${search}%`, `%${search}%`);
    }

    query += ' ORDER BY l.created_at DESC LIMIT ? OFFSET ?';
    params.push(limit, offset);

    const listings = await env.DB.prepare(query).bind(...params).all();
    const formattedListings = (listings.results || []).map(formatListingRecord);

    return new Response(JSON.stringify({
      listings: formattedListings,
      total: formattedListings.length
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  } catch (error) {
    console.error('Get listings error:', error);
    return new Response(JSON.stringify({
      error: 'Failed to fetch listings',
      details: error.message
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

async function handleCreateListing(request, env, corsHeaders) {
  try {
    const user = await getUserFromSession(request, env);
    if (!user) {
      return new Response(JSON.stringify({ error: 'Authentication required' }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    const body = await request.json();
    const { payload, error } = buildListingPayload(body);

    if (error) {
      return new Response(JSON.stringify({ error }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }

    const result = await env.DB.prepare(
      `INSERT INTO listings (
        user_id, title, description, price, category, condition, listing_type, price_period,
        negotiable, contact_method, phone_number, image_urls, location, availability_start,
        availability_end, housing_type, bedrooms, bathrooms, furnished, utilities_included,
        parking_available, pet_friendly, roommates_allowed, lease_transfer_fee, address_text,
        sublease_notes, status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      user.user_id,
      payload.title,
      payload.description,
      payload.price,
      payload.category,
      payload.condition,
      payload.listing_type,
      payload.price_period,
      payload.negotiable ? 1 : 0,
      payload.contact_method,
      payload.phone_number,
      payload.image_urls,
      payload.location,
      payload.availability_start,
      payload.availability_end,
      payload.housing_type,
      payload.bedrooms,
      payload.bathrooms,
      payload.furnished ? 1 : 0,
      payload.utilities_included ? 1 : 0,
      payload.parking_available ? 1 : 0,
      payload.pet_friendly ? 1 : 0,
      payload.roommates_allowed ? 1 : 0,
      payload.lease_transfer_fee,
      payload.address_text,
      payload.sublease_notes,
      'active'
    ).run();

    return new Response(JSON.stringify({
      message: 'Listing created successfully',
      id: result.meta.last_row_id,
      listing: formatListingRecord({
        id: result.meta.last_row_id,
        user_id: user.user_id,
        status: 'active',
        ...payload
      })
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  } catch (error) {
    console.error('Create listing error:', error);
    return new Response(JSON.stringify({
      error: 'Failed to create listing',
      details: error.message
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

async function handleGetListing(listingId, env, corsHeaders) {
  try {
    const listing = await env.DB.prepare(`
      SELECT l.*, u.profile_name as seller_name, u.email as seller_email, u.phone_number as seller_phone, u.is_verified as seller_verified, u.created_at as seller_created_at
      FROM listings l 
      JOIN users u ON l.user_id = u.id 
      WHERE l.id = ? AND l.status = 'active'
    `).bind(listingId).first();
    
    if (!listing) {
      return new Response(JSON.stringify({ error: 'Listing not found' }), {
        status: 404,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    return new Response(JSON.stringify({ listing: formatListingRecord(listing) }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    console.error('Get listing error:', error);
    return new Response(JSON.stringify({ 
      error: 'Failed to fetch listing' 
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

async function handleUpdateListing(listingId, request, env, corsHeaders) {
  try {
    const user = await getUserFromSession(request, env);
    if (!user) {
      return new Response(JSON.stringify({ error: 'Authentication required' }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    const listing = await env.DB.prepare(
      'SELECT * FROM listings WHERE id = ?'
    ).bind(listingId).first();
    
    if (!listing) {
      return new Response(JSON.stringify({ error: 'Listing not found' }), {
        status: 404,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    if (listing.user_id !== user.user_id) {
      return new Response(JSON.stringify({ error: 'Not authorized to update this listing' }), {
        status: 403,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    const body = await request.json();
    const mergedBody = {
      ...listing,
      ...body,
      imageUrls: body.imageUrls ?? parseImageUrls(listing.image_urls)
    };
    const { payload, error } = buildListingPayload(mergedBody);

    if (error) {
      return new Response(JSON.stringify({ error }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }

    const nextStatus = body.status || listing.status;

    await env.DB.prepare(`
      UPDATE listings 
      SET title = ?, description = ?, price = ?, category = ?, condition = ?, listing_type = ?, price_period = ?,
          negotiable = ?, contact_method = ?, phone_number = ?, image_urls = ?, location = ?, availability_start = ?,
          availability_end = ?, housing_type = ?, bedrooms = ?, bathrooms = ?, furnished = ?, utilities_included = ?,
          parking_available = ?, pet_friendly = ?, roommates_allowed = ?, lease_transfer_fee = ?, address_text = ?,
          sublease_notes = ?, status = ?, updated_at = datetime('now')
      WHERE id = ?
    `).bind(
      payload.title,
      payload.description,
      payload.price,
      payload.category,
      payload.condition,
      payload.listing_type,
      payload.price_period,
      payload.negotiable ? 1 : 0,
      payload.contact_method,
      payload.phone_number,
      payload.image_urls,
      payload.location,
      payload.availability_start,
      payload.availability_end,
      payload.housing_type,
      payload.bedrooms,
      payload.bathrooms,
      payload.furnished ? 1 : 0,
      payload.utilities_included ? 1 : 0,
      payload.parking_available ? 1 : 0,
      payload.pet_friendly ? 1 : 0,
      payload.roommates_allowed ? 1 : 0,
      payload.lease_transfer_fee,
      payload.address_text,
      payload.sublease_notes,
      nextStatus,
      listingId
    ).run();

    return new Response(JSON.stringify({
      message: 'Listing updated successfully',
      listing: formatListingRecord({
        ...listing,
        ...payload,
        status: nextStatus
      })
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    console.error('Update listing error:', error);
    return new Response(JSON.stringify({ 
      error: 'Failed to update listing' 
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

async function handleDeleteListing(listingId, request, env, corsHeaders) {
  try {
    const user = await getUserFromSession(request, env);
    if (!user) {
      return new Response(JSON.stringify({ error: 'Authentication required' }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    const listing = await env.DB.prepare(
      'SELECT user_id FROM listings WHERE id = ?'
    ).bind(listingId).first();
    
    if (!listing) {
      return new Response(JSON.stringify({ error: 'Listing not found' }), {
        status: 404,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    if (listing.user_id !== user.user_id) {
      return new Response(JSON.stringify({ error: 'Not authorized to delete this listing' }), {
        status: 403,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    await env.DB.prepare(
      'UPDATE listings SET status = ?, updated_at = datetime("now") WHERE id = ?'
    ).bind('deleted', listingId).run();
    
    return new Response(JSON.stringify({ 
      message: 'Listing deleted successfully' 
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    console.error('Delete listing error:', error);
    return new Response(JSON.stringify({ 
      error: 'Failed to delete listing' 
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

// Messages functions (Phase 1)
// Get messages for a specific listing (used by listing detail page)
async function handleGetListingMessages(listingId, request, env, corsHeaders) {
  try {
    const user = await getUserFromSession(request, env);
    if (!user) {
      return new Response(JSON.stringify({ error: 'Authentication required' }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    // Find the conversation for this listing and user
    const conversation = await env.DB.prepare(`
      SELECT id FROM conversations 
      WHERE listing_id = ? AND (buyer_id = ? OR seller_id = ?)
    `).bind(listingId, user.user_id, user.user_id).first();
    
    if (!conversation) {
      return new Response(JSON.stringify({ messages: [] }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    // Get messages for this conversation
    const messages = await env.DB.prepare(`
      SELECT m.*, u.profile_name as sender_name, u.id as sender_id
      FROM messages m
      JOIN users u ON m.sender_id = u.id
      WHERE m.conversation_id = ?
      ORDER BY m.created_at ASC
    `).bind(conversation.id).all();
    
    // Mark messages as read for current user
    await env.DB.prepare(`
      UPDATE messages 
      SET is_read = 1 
      WHERE conversation_id = ? AND sender_id != ?
    `).bind(conversation.id, user.user_id).run();
    
    return new Response(JSON.stringify({ 
      messages: messages.results || [],
      conversationId: conversation.id
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    console.error('Get listing messages error:', error);
    return new Response(JSON.stringify({ 
      error: 'Failed to fetch messages' 
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

async function handleSendMessage(request, env, corsHeaders) {
  try {
    const user = await getUserFromSession(request, env);
    if (!user) {
      return new Response(JSON.stringify({ error: 'Authentication required' }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    const { listing_id, receiver_id, message } = await request.json();
    const listingId = Number(listing_id);
    const receiverId = Number(receiver_id);
    
    if (!listingId || !receiverId || !message || message.trim().length === 0) {
      return new Response(JSON.stringify({ error: 'Listing ID, receiver ID, and message are required' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    // Validate message length
    if (message.length > 500) {
      return new Response(JSON.stringify({ error: 'Message is too long (max 500 characters)' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    // Verify listing exists and get listing info
    const listing = await env.DB.prepare(
      'SELECT id, user_id as seller_id, title FROM listings WHERE id = ? AND status = "active"'
    ).bind(listingId).first();
    
    if (!listing) {
      return new Response(JSON.stringify({ error: 'Listing not found or no longer active' }), {
        status: 404,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    // Verify receiver exists and is different from sender
    const receiver = await env.DB.prepare(
      'SELECT id FROM users WHERE id = ?'
    ).bind(receiverId).first();
    
    if (!receiver) {
      return new Response(JSON.stringify({ error: 'Receiver not found' }), {
        status: 404,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    // Prevent users from messaging themselves
    if (user.user_id === receiverId) {
      return new Response(JSON.stringify({ error: 'Cannot send messages to yourself' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    // Determine buyer and seller IDs
    const buyerId = user.user_id === listing.seller_id ? receiverId : user.user_id;
    const sellerId = listing.seller_id;
    
    // Find or create conversation
    let conversation = await env.DB.prepare(`
      SELECT id FROM conversations 
      WHERE listing_id = ? AND buyer_id = ? AND seller_id = ?
    `).bind(listingId, buyerId, sellerId).first();
    
    if (!conversation) {
      // Create new conversation
      const conversationResult = await env.DB.prepare(`
        INSERT INTO conversations (listing_id, buyer_id, seller_id, last_message_preview, last_message_at)
        VALUES (?, ?, ?, ?, datetime('now'))
      `).bind(listingId, buyerId, sellerId, message.substring(0, 100)).run();
      
      conversation = { id: conversationResult.meta.last_row_id };
    } else {
      // Update existing conversation
      await env.DB.prepare(`
        UPDATE conversations 
        SET last_message_preview = ?, last_message_at = datetime('now')
        WHERE id = ?
      `).bind(message.substring(0, 100), conversation.id).run();
    }
    
    // Insert message
    const messageResult = await env.DB.prepare(
      'INSERT INTO messages (conversation_id, sender_id, message) VALUES (?, ?, ?)'
    ).bind(conversation.id, user.user_id, message.trim()).run();
    
    return new Response(JSON.stringify({ 
      message: 'Message sent successfully',
      messageId: messageResult.meta.last_row_id,
      conversationId: conversation.id
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    console.error('Send message error:', error);
    return new Response(JSON.stringify({ 
      error: 'Failed to send message' 
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

// Favorites functions
async function handleAddFavorite(listingId, request, env, corsHeaders) {
  try {
    const user = await getUserFromSession(request, env);
    if (!user) {
      return new Response(JSON.stringify({ error: 'Authentication required' }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    // Check if listing exists
    const listing = await env.DB.prepare(
      'SELECT id FROM listings WHERE id = ? AND status = "active"'
    ).bind(listingId).first();
    
    if (!listing) {
      return new Response(JSON.stringify({ error: 'Listing not found' }), {
        status: 404,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    // Check if already favorited
    const existingFavorite = await env.DB.prepare(
      'SELECT id FROM favorites WHERE user_id = ? AND listing_id = ?'
    ).bind(user.user_id, listingId).first();
    
    if (existingFavorite) {
      return new Response(JSON.stringify({ error: 'Already favorited' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    await env.DB.prepare(
      'INSERT INTO favorites (user_id, listing_id) VALUES (?, ?)'
    ).bind(user.user_id, listingId).run();
    
    return new Response(JSON.stringify({ 
      message: 'Added to favorites' 
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    console.error('Add favorite error:', error);
    return new Response(JSON.stringify({ 
      error: 'Failed to add favorite' 
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

async function handleRemoveFavorite(listingId, request, env, corsHeaders) {
  try {
    const user = await getUserFromSession(request, env);
    if (!user) {
      return new Response(JSON.stringify({ error: 'Authentication required' }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    await env.DB.prepare(
      'DELETE FROM favorites WHERE user_id = ? AND listing_id = ?'
    ).bind(user.user_id, listingId).run();
    
    return new Response(JSON.stringify({ 
      message: 'Removed from favorites' 
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    console.error('Remove favorite error:', error);
    return new Response(JSON.stringify({ 
      error: 'Failed to remove favorite' 
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

async function handleGetFavorites(request, env, corsHeaders) {
  try {
    const user = await getUserFromSession(request, env);
    if (!user) {
      return new Response(JSON.stringify({ error: 'Authentication required' }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    const favorites = await env.DB.prepare(`
      SELECT l.*, u.profile_name as seller_name, f.created_at as favorited_at
      FROM favorites f
      JOIN listings l ON f.listing_id = l.id
      JOIN users u ON l.user_id = u.id
      WHERE f.user_id = ? AND l.status = 'active'
      ORDER BY f.created_at DESC
    `).bind(user.user_id).all();
    
    return new Response(JSON.stringify({ 
      favorites: (favorites.results || []).map(formatListingRecord)
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    console.error('Get favorites error:', error);
    return new Response(JSON.stringify({ 
      error: 'Failed to fetch favorites' 
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

async function handleGetUserProfile(userId, env, corsHeaders) {
  try {
    const user = await env.DB.prepare(
      'SELECT id, profile_name, bio, created_at FROM users WHERE id = ?'
    ).bind(userId).first();
    
    if (!user) {
      return new Response(JSON.stringify({ error: 'User not found' }), {
        status: 404,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    // Get user's active listings count
    const listingsCount = await env.DB.prepare(
      'SELECT COUNT(*) as count FROM listings WHERE user_id = ? AND status = "active"'
    ).bind(userId).first();
    
    return new Response(JSON.stringify({ 
      user: {
        ...user,
        listingsCount: listingsCount.count || 0
      }
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    console.error('Get user profile error:', error);
    return new Response(JSON.stringify({ 
      error: 'Failed to fetch user profile' 
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

async function handleGetUserListings(userId, env, corsHeaders) {
  try {
    const stmt = env.DB.prepare(`
      SELECT id, title, price, image_urls, created_at, status, category, condition, listing_type, price_period, availability_start, availability_end, housing_type, location
      FROM listings 
      WHERE user_id = ? AND status = 'active'
      ORDER BY created_at DESC
    `);
    
    const { results } = await stmt.bind(userId).all();
    
    return new Response(JSON.stringify({
      listings: (results || []).map(formatListingRecord)
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: 'Failed to fetch user listings' }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

// Image upload function
async function handleImageUpload(request, env, corsHeaders) {
  try {
    const user = await getUserFromSession(request, env);
    if (!user) {
      return new Response(JSON.stringify({ error: 'Authentication required' }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }

    const formData = await request.formData();
    const file = formData.get('image');
    
    if (!file) {
      return new Response(JSON.stringify({ error: 'No image file provided' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }

    // Validate file type
    const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/webp'];
    if (!allowedTypes.includes(file.type)) {
      return new Response(JSON.stringify({ error: 'Invalid file type. Only JPEG, PNG, and WebP are allowed.' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }

    // Validate file size (max 5MB)
    const maxSize = 5 * 1024 * 1024; // 5MB
    if (file.size > maxSize) {
      return new Response(JSON.stringify({ error: 'File too large. Maximum size is 5MB.' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }

    // Generate unique filename
    const timestamp = Date.now();
    const randomId = crypto.randomUUID().substring(0, 8);
    const fileExtension = file.name.split('.').pop().toLowerCase();
    const fileName = `listings/${user.user_id}/${timestamp}-${randomId}.${fileExtension}`;

    try {
      // Upload to R2
      await env.IMAGES_BUCKET.put(fileName, file.stream(), {
        httpMetadata: {
          contentType: file.type,
        },
      });

      // Generate public URL using your R2.dev subdomain
      const imageUrl = `https://pub-046354251a014b5c9b1ab9aa3bad8c8f.r2.dev/${fileName}`;
      
      return new Response(JSON.stringify({ 
        message: 'Image uploaded successfully',
        imageUrl: imageUrl
      }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
      
    } catch (uploadError) {
      console.error('R2 upload error:', uploadError);
      return new Response(JSON.stringify({ 
        error: 'Failed to upload image to storage',
        details: uploadError.message 
      }), {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
  } catch (error) {
    console.error('Image upload error:', error);
    return new Response(JSON.stringify({ 
      error: 'Failed to process image upload',
      details: error.message 
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

async function handleForgotPassword(request, env, corsHeaders) {
  try {
    const { email, captchaToken } = await request.json();
    
    if (!email || !captchaToken) {
      return new Response(JSON.stringify({ error: 'Email and CAPTCHA are required' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    // Verify CAPTCHA
    const isCaptchaValid = await verifyCaptcha(captchaToken, env);
    if (!isCaptchaValid) {
      return new Response(JSON.stringify({ error: 'CAPTCHA verification failed. Please try again.' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    // Check if email format is valid
    if (!email.endsWith('@fsu.edu') && !email.endsWith('@gmail.com')) {
      return new Response(JSON.stringify({ error: 'Must use FSU email or Gmail for testing' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    // Find user - but don't reveal if email doesn't exist for security
    const user = await env.DB.prepare(
      'SELECT id, email, is_verified FROM users WHERE email = ?'
    ).bind(email).first();
    
    if (user && user.is_verified) {
      // Generate reset token
      const resetToken = crypto.randomUUID();
      const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour from now
      
      // Clear any existing reset tokens for this user
      await env.DB.prepare(
        'UPDATE users SET reset_token = ?, reset_token_expires = ? WHERE id = ?'
      ).bind(resetToken, expiresAt.toISOString(), user.id).run();
      
      // Send reset email
      const emailSent = await sendPasswordResetEmail(email, resetToken, env);
      
      if (!emailSent) {
        return new Response(JSON.stringify({ 
          error: 'Failed to send reset email. Please try again.' 
        }), {
          status: 500,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }
    }
    
    // Always return success message for security (don't reveal if email exists)
    return new Response(JSON.stringify({ 
      message: 'If an account with that email exists, you will receive a password reset link shortly.' 
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    console.error('Forgot password error:', error);
    return new Response(JSON.stringify({ 
      error: 'Failed to process request',
      details: error.message 
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

async function handleVerifyResetToken(request, env, url) {
  try {
    const token = url.searchParams.get('token');
    
    if (!token) {
      return buildFrontendRedirect(env, '/reset-password/', {
        status: 'invalid',
        message: 'Missing reset token'
      });
    }
    
    const user = await env.DB.prepare(
      'SELECT id, email, reset_token_expires FROM users WHERE reset_token = ?'
    ).bind(token).first();
    
    if (!user) {
      return buildFrontendRedirect(env, '/reset-password/', {
        status: 'invalid',
        message: 'Invalid or expired reset token'
      });
    }
    
    // Check if token is expired
    const now = new Date();
    const expiresAt = new Date(user.reset_token_expires);
    
    if (now > expiresAt) {
      // Clean up expired token
      await env.DB.prepare(
        'UPDATE users SET reset_token = NULL, reset_token_expires = NULL WHERE id = ?'
      ).bind(user.id).run();
      
      return buildFrontendRedirect(env, '/reset-password/', {
        status: 'expired',
        message: 'Reset token has expired. Please request a new one.'
      });
    }
    
    // Token is valid, redirect to reset form with token
    return buildFrontendRedirect(env, '/reset-password/', {
      token,
      email: user.email
    });
    
  } catch (error) {
    console.error('Reset token verification error:', error);
    return buildFrontendRedirect(env, '/reset-password/', {
      status: 'error',
      message: 'An error occurred during verification'
    });
  }
}

async function handleResetPassword(request, env, corsHeaders) {
  try {
    const { token, password, captchaToken } = await request.json();
    
    if (!token || !password || !captchaToken) {
      return new Response(JSON.stringify({ error: 'Token, password, and CAPTCHA are required' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    // Verify CAPTCHA
    const isCaptchaValid = await verifyCaptcha(captchaToken, env);
    if (!isCaptchaValid) {
      return new Response(JSON.stringify({ error: 'CAPTCHA verification failed. Please try again.' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    // Validate password strength
    if (password.length < 8) {
      return new Response(JSON.stringify({ error: 'Password must be at least 8 characters long' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    // Find user with valid token
    const user = await env.DB.prepare(
      'SELECT id, email, reset_token_expires FROM users WHERE reset_token = ?'
    ).bind(token).first();
    
    if (!user) {
      return new Response(JSON.stringify({ error: 'Invalid or expired reset token' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    // Check if token is expired
    const now = new Date();
    const expiresAt = new Date(user.reset_token_expires);
    
    if (now > expiresAt) {
      // Clean up expired token
      await env.DB.prepare(
        'UPDATE users SET reset_token = NULL, reset_token_expires = NULL WHERE id = ?'
      ).bind(user.id).run();
      
      return new Response(JSON.stringify({ error: 'Reset token has expired. Please request a new one.' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    // Hash new password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Update password and clear reset token
    await env.DB.prepare(
      'UPDATE users SET password_hash = ?, reset_token = NULL, reset_token_expires = NULL, updated_at = datetime("now") WHERE id = ?'
    ).bind(hashedPassword, user.id).run();
    
    // Send confirmation email
    await sendPasswordResetConfirmationEmail(user.email, env);
    
    return new Response(JSON.stringify({ 
      message: 'Password reset successfully! You can now log in with your new password.' 
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    console.error('Reset password error:', error);
    return new Response(JSON.stringify({ 
      error: 'Failed to reset password',
      details: error.message 
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

async function sendPasswordResetEmail(email, token, env) {
  try {
    if (!env.RESEND_API_KEY) {
      console.error('RESEND_API_KEY is not configured');
      return false;
    }

    const baseUrl = getWorkerBaseUrl(env);
    const resetUrl = `${baseUrl}/verify-reset?token=${token}`;
    
    const emailHtml = `
      <!DOCTYPE html>
      <html>
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
        </head>
        <body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f9f9f9;">
          
          <table width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color: #f9f9f9;">
            <tr>
              <td align="center" style="padding: 40px 20px;">
                <table width="100%" style="max-width: 600px;" cellpadding="0" cellspacing="0" border="0">
                  
                  <!-- Header with rounded top corners -->
                  <tr>
                    <td style="background: linear-gradient(135deg, #8B2635, #6B1B2A); background-color: #8B2635; padding: 40px 30px; text-align: center; border-radius: 12px 12px 0 0;">
                      <div style="display: inline-block; width: 60px; height: 60px; background-color: rgba(255, 255, 255, 0.15); border-radius: 12px; border: 2px solid rgba(255, 255, 255, 0.2); color: white; font-weight: bold; font-size: 24px; line-height: 56px; text-align: center; margin-bottom: 15px;">SE</div>
                      <h1 style="margin: 0; font-size: 28px; font-weight: bold; color: white;">Password Reset Request</h1>
                    </td>
                  </tr>
                  
                  <!-- Content with rounded bottom corners -->
                  <tr>
                    <td style="background-color: #ffffff; padding: 40px 30px; border-radius: 0 0 12px 12px;">
                      
                      <h2 style="color: #2C3E50; font-size: 24px; margin: 0 0 20px 0; font-weight: 600;">Reset Your Password</h2>
                      
                      <p style="color: #5A6C7D; margin: 0 0 15px 0; font-size: 16px; line-height: 1.6;">Hi there!</p>
                      
                      <p style="color: #5A6C7D; margin: 0 0 25px 0; font-size: 16px; line-height: 1.6;">We received a request to reset the password for your Spear Exchange account. If you made this request, click the button below to reset your password:</p>
                      
                      <!-- Button -->
                      <div style="text-align: center; margin: 25px 0;">
                        <a href="${resetUrl}" style="display: inline-block; background: linear-gradient(135deg, #8B2635, #6B1B2A); background-color: #8B2635; color: white; padding: 15px 30px; text-decoration: none; border-radius: 8px; font-weight: 600; font-size: 16px;">Reset My Password</a>
                      </div>
                      
                      <!-- Warning Box -->
                      <div style="background-color: #FEF3CD; border: 1px solid #F59E0B; border-radius: 8px; padding: 15px; margin: 25px 0;">
                        <p style="color: #92400E; margin: 0; font-weight: 600; font-size: 14px;">⚠️ Security Notice: This link expires in 1 hour for your security.</p>
                      </div>
                      
                      <p style="color: #5A6C7D; margin: 20px 0 10px 0; font-size: 16px;">Or copy and paste this link into your browser:</p>
                      
                      <div style="background-color: #f0f0f0; padding: 15px; border-radius: 8px; margin: 15px 0; word-break: break-all; font-family: monospace; font-size: 14px; color: #8B2635; border: 1px solid #e0e0e0;">${resetUrl}</div>
                      
                      <p style="color: #5A6C7D; margin: 25px 0 0 0; font-size: 16px;"><strong>Didn't request this?</strong> If you didn't request a password reset, please ignore this email. Your password will remain unchanged.</p>
                      
                      <!-- Footer -->
                      <div style="border-top: 1px solid #e2e8f0; padding-top: 25px; margin-top: 30px; color: #9CA3AF; font-size: 14px;">
                        <p style="margin: 0 0 8px 0;"><strong style="color: #5A6C7D;">Go Noles! 🏈</strong></p>
                        <p style="margin: 0 0 15px 0;">The Spear Exchange Team</p>
                        <p style="margin: 0;"><em>This email was sent to ${email}. If you have any concerns, please contact our support team.</em></p>
                      </div>
                      
                    </td>
                  </tr>
                </table>
              </td>
            </tr>
          </table>
          
        </body>
      </html>
    `;

    const response = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${env.RESEND_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: 'The Spear Exchange <noreply@lennypaz.com>',
        to: email,
        subject: 'Reset your password - The Spear Exchange',
        html: emailHtml,
      }),
    });

    if (!response.ok) {
      const errorData = await response.json();
      console.error('Reset email sending failed:', errorData);
      return false;
    }

    const result = await response.json();
    console.log('Reset email sent successfully:', result.id);
    return true;
  } catch (error) {
    console.error('Reset email sending error:', error);
    return false;
  }
}

async function sendPasswordResetConfirmationEmail(email, env) {
  try {
    if (!env.RESEND_API_KEY) {
      console.error('RESEND_API_KEY is not configured');
      return;
    }

    const emailHtml = `
      <!DOCTYPE html>
      <html>
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
        </head>
        <body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f9f9f9;">
          
          <table width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color: #f9f9f9;">
            <tr>
              <td align="center" style="padding: 40px 20px;">
                <table width="100%" style="max-width: 600px;" cellpadding="0" cellspacing="0" border="0">
                  
                  <!-- Header with rounded top corners -->
                  <tr>
                    <td style="background: linear-gradient(135deg, #10B981, #059669); background-color: #10B981; padding: 40px 30px; text-align: center; border-radius: 12px 12px 0 0;">
                      <div style="display: inline-block; width: 60px; height: 60px; background-color: rgba(255, 255, 255, 0.15); border-radius: 12px; border: 2px solid rgba(255, 255, 255, 0.2); color: white; font-weight: bold; font-size: 24px; line-height: 56px; text-align: center; margin-bottom: 15px;">✓</div>
                      <h1 style="margin: 0; font-size: 28px; font-weight: bold; color: white;">Password Successfully Reset</h1>
                    </td>
                  </tr>
                  
                  <!-- Content with rounded bottom corners -->
                  <tr>
                    <td style="background-color: #ffffff; padding: 40px 30px; border-radius: 0 0 12px 12px;">
                      
                      <h2 style="color: #2C3E50; font-size: 24px; margin: 0 0 20px 0; font-weight: 600;">Your Password Has Been Updated</h2>
                      
                      <!-- Success Box -->
                      <div style="background-color: #D1FAE5; border: 1px solid #10B981; border-radius: 8px; padding: 20px; margin: 25px 0; text-align: center;">
                        <p style="color: #065F46; margin: 0; font-weight: 600; font-size: 18px;">Your password has been successfully reset!</p>
                      </div>
                      
                      <p style="color: #5A6C7D; margin: 0 0 25px 0; font-size: 16px; line-height: 1.6;">Your Spear Exchange account password has been successfully updated. You can now log in using your new password.</p>
                      
                      <p style="color: #5A6C7D; margin: 0 0 10px 0; font-size: 16px; font-weight: 600;">For your security:</p>
                      <ul style="color: #5A6C7D; padding-left: 20px; margin: 0 0 25px 0; font-size: 15px; line-height: 1.6;">
                        <li style="margin-bottom: 6px;">Make sure to keep your new password secure</li>
                        <li style="margin-bottom: 6px;">Don't share your password with anyone</li>
                        <li>If you didn't make this change, please contact our support team immediately</li>
                      </ul>
                      
                      <!-- Footer -->
                      <div style="border-top: 1px solid #e2e8f0; padding-top: 25px; margin-top: 30px; color: #9CA3AF; font-size: 14px;">
                        <p style="margin: 0 0 8px 0;"><strong style="color: #5A6C7D;">Go Noles! 🏈</strong></p>
                        <p style="margin: 0 0 15px 0;">The Spear Exchange Team</p>
                        <p style="margin: 0;"><em>This email was sent to ${email} for security purposes.</em></p>
                      </div>
                      
                    </td>
                  </tr>
                </table>
              </td>
            </tr>
          </table>
          
        </body>
      </html>
    `;

    await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${env.RESEND_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: 'The Spear Exchange <noreply@lennypaz.com>',
        to: email,
        subject: 'Password reset confirmation - The Spear Exchange',
        html: emailHtml,
      }),
    });
  } catch (error) {
    console.error('Confirmation email error:', error);
    // Don't fail the reset if confirmation email fails
  }
}

// Conversations functions (Phase 2 - Full Messages Page)
async function handleGetConversations(request, env, corsHeaders) {
  try {
    const user = await getUserFromSession(request, env);
    if (!user) {
      return new Response(JSON.stringify({ error: 'Authentication required' }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    // Get all conversations where user is either buyer or seller
    const conversations = await env.DB.prepare(`
      SELECT 
        c.id,
        c.listing_id,
        c.buyer_id,
        c.seller_id,
        c.last_message_preview,
        c.last_message_at,
        c.created_at,
        l.title as listing_title,
        l.price as listing_price,
        l.image_urls as listing_image_urls,
        l.listing_type as listing_type,
        l.price_period as listing_price_period,
        l.category as listing_category,
        l.availability_start as listing_availability_start,
        l.availability_end as listing_availability_end,
        l.housing_type as listing_housing_type,
        l.address_text as listing_address_text,
        l.status as listing_status,
        buyer.profile_name as buyer_name,
        seller.profile_name as seller_name,
        -- Count unread messages for current user
        (
          SELECT COUNT(*) 
          FROM messages m 
          WHERE m.conversation_id = c.id 
            AND m.sender_id != ? 
            AND m.is_read = 0
        ) as unread_count
      FROM conversations c
      JOIN listings l ON c.listing_id = l.id
      JOIN users buyer ON c.buyer_id = buyer.id
      JOIN users seller ON c.seller_id = seller.id
      WHERE c.buyer_id = ? OR c.seller_id = ?
      ORDER BY c.last_message_at DESC
    `).bind(user.user_id, user.user_id, user.user_id).all();
    
    // Format conversations with additional info
    const formattedConversations = conversations.results?.map(conv => {
      // Parse image URLs
      let imageUrls = [];
      if (conv.listing_image_urls) {
        try {
          imageUrls = JSON.parse(conv.listing_image_urls);
        } catch (e) {
          imageUrls = [];
        }
      }
      
      // Determine other user info
      const isUserBuyer = conv.buyer_id === user.user_id;
      const otherUserName = isUserBuyer ? conv.seller_name : conv.buyer_name;
      const otherUserId = isUserBuyer ? conv.seller_id : conv.buyer_id;
      
      return {
        id: conv.id,
        listing: {
          id: conv.listing_id,
          title: conv.listing_title,
          price: conv.listing_price,
          image_url: imageUrls[0] || null,
          status: conv.listing_status,
          listing_type: conv.listing_type || LISTING_TYPE_GOODS,
          price_period: conv.listing_price_period || PRICE_PERIOD_ONE_TIME,
          category: conv.listing_category,
          availability_start: conv.listing_availability_start,
          availability_end: conv.listing_availability_end,
          housing_type: conv.listing_housing_type,
          address_text: conv.listing_address_text
        },
        other_user: {
          id: otherUserId,
          name: otherUserName,
          role: isUserBuyer ? 'seller' : 'buyer'
        },
        last_message_preview: conv.last_message_preview,
        last_message_at: conv.last_message_at,
        unread_count: conv.unread_count,
        created_at: conv.created_at
      };
    }) || [];
    
    return new Response(JSON.stringify({
      conversations: formattedConversations
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    console.error('Get conversations error:', error);
    return new Response(JSON.stringify({
      error: 'Failed to fetch conversations',
      details: error.message
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

async function handleGetConversationMessages(conversationId, request, env, corsHeaders) {
  try {
    const user = await getUserFromSession(request, env);
    if (!user) {
      return new Response(JSON.stringify({ error: 'Authentication required' }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    // Verify user is part of this conversation
    const conversation = await env.DB.prepare(
      'SELECT buyer_id, seller_id, listing_id FROM conversations WHERE id = ?'
    ).bind(conversationId).first();
    
    if (!conversation) {
      return new Response(JSON.stringify({ error: 'Conversation not found' }), {
        status: 404,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    if (conversation.buyer_id !== user.user_id && conversation.seller_id !== user.user_id) {
      return new Response(JSON.stringify({ error: 'Access denied' }), {
        status: 403,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    // Get messages for this conversation
    const messages = await env.DB.prepare(`
      SELECT 
        m.id,
        m.message,
        m.created_at,
        m.is_read,
        m.sender_id,
        u.profile_name as sender_name
      FROM messages m
      JOIN users u ON m.sender_id = u.id
      WHERE m.conversation_id = ?
      ORDER BY m.created_at ASC
    `).bind(conversationId).all();
    
    // Get listing info for context
    const listing = await env.DB.prepare(`
      SELECT l.id, l.title, l.price, l.image_urls, l.status, l.listing_type, l.price_period, l.category,
             l.availability_start, l.availability_end, l.housing_type, l.address_text,
             u.profile_name as seller_name
      FROM listings l
      JOIN users u ON l.user_id = u.id
      WHERE l.id = ?
    `).bind(conversation.listing_id).first();
    
    // Parse image URLs
    let imageUrls = [];
    if (listing?.image_urls) {
      try {
        imageUrls = JSON.parse(listing.image_urls);
      } catch (e) {
        imageUrls = [];
      }
    }
    
    return new Response(JSON.stringify({
      messages: messages.results || [],
      listing: {
        id: listing?.id,
        title: listing?.title,
        price: listing?.price,
        image_url: imageUrls[0] || null,
        status: listing?.status,
        listing_type: listing?.listing_type || LISTING_TYPE_GOODS,
        price_period: listing?.price_period || PRICE_PERIOD_ONE_TIME,
        category: listing?.category,
        availability_start: listing?.availability_start,
        availability_end: listing?.availability_end,
        housing_type: listing?.housing_type,
        address_text: listing?.address_text,
        seller_name: listing?.seller_name
      }
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    console.error('Get conversation messages error:', error);
    return new Response(JSON.stringify({
      error: 'Failed to fetch messages',
      details: error.message
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

async function handleSendConversationMessage(conversationId, request, env, corsHeaders) {
  try {
    // Check if this is an internal request from the Durable Object
    const isInternal = request.headers.get('X-Internal-Request') === 'true';
    
    let userId, userData;
    
    if (isInternal) {
      // For internal requests, get user ID from header
      userId = parseInt(request.headers.get('X-User-ID'));
      userData = await env.DB.prepare('SELECT profile_name FROM users WHERE id = ?')
        .bind(userId).first();
    } else {
      // For external requests, verify auth normally
      const user = await getUserFromSession(request, env);
      if (!user) {
        return new Response(JSON.stringify({ error: 'Authentication required' }), {
          status: 401,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }
      userId = user.user_id;
      userData = { profile_name: user.profile_name };
    }
    
    const { message } = await request.json();
    
    if (!message || message.trim().length === 0) {
      return new Response(JSON.stringify({ error: 'Message is required' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    // Validate message length
    if (message.length > 500) {
      return new Response(JSON.stringify({ error: 'Message is too long (max 500 characters)' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    // Verify user is part of this conversation
    const conversation = await env.DB.prepare(
      'SELECT buyer_id, seller_id, listing_id FROM conversations WHERE id = ?'
    ).bind(conversationId).first();
    
    if (!conversation) {
      return new Response(JSON.stringify({ error: 'Conversation not found' }), {
        status: 404,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    if (conversation.buyer_id !== userId && conversation.seller_id !== userId) {
      return new Response(JSON.stringify({ error: 'Access denied' }), {
        status: 403,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    // Check if listing is still active
    const listing = await env.DB.prepare(
      'SELECT status FROM listings WHERE id = ?'
    ).bind(conversation.listing_id).first();
    
    if (!listing || listing.status !== 'active') {
      return new Response(JSON.stringify({ error: 'Cannot send message - listing is no longer active' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    // Insert message
    const messageResult = await env.DB.prepare(
      'INSERT INTO messages (conversation_id, sender_id, message) VALUES (?, ?, ?)'
    ).bind(conversationId, userId, message.trim()).run();
    
    // Update conversation with last message info
    await env.DB.prepare(`
      UPDATE conversations 
      SET last_message_preview = ?, last_message_at = datetime('now')
      WHERE id = ?
    `).bind(message.substring(0, 100), conversationId).run();
    
    return new Response(JSON.stringify({
      message: 'Message sent successfully',
      messageId: messageResult.meta.last_row_id
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    console.error('Send conversation message error:', error);
    return new Response(JSON.stringify({
      error: 'Failed to send message',
      details: error.message
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

async function handleMarkMessagesAsRead(conversationId, request, env, corsHeaders) {
  try {
    // Check if this is an internal request from the Durable Object
    const isInternal = request.headers.get('X-Internal-Request') === 'true';
    
    let userId;
    
    if (isInternal) {
      // For internal requests, get user ID from header
      userId = parseInt(request.headers.get('X-User-ID'));
    } else {
      // For external requests, verify auth normally
      const user = await getUserFromSession(request, env);
      if (!user) {
        return new Response(JSON.stringify({ error: 'Authentication required' }), {
          status: 401,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }
      userId = user.user_id;
    }
    
    // Verify user is part of this conversation
    const conversation = await env.DB.prepare(
      'SELECT buyer_id, seller_id FROM conversations WHERE id = ?'
    ).bind(conversationId).first();
    
    if (!conversation) {
      return new Response(JSON.stringify({ error: 'Conversation not found' }), {
        status: 404,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    if (conversation.buyer_id !== userId && conversation.seller_id !== userId) {
      return new Response(JSON.stringify({ error: 'Access denied' }), {
        status: 403,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    // Mark all messages in this conversation as read for current user
    // (only messages sent by other users)
    await env.DB.prepare(`
      UPDATE messages 
      SET is_read = 1 
      WHERE conversation_id = ? AND sender_id != ? AND is_read = 0
    `).bind(conversationId, userId).run();
    
    return new Response(JSON.stringify({
      message: 'Messages marked as read'
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    console.error('Mark messages as read error:', error);
    return new Response(JSON.stringify({
      error: 'Failed to mark messages as read',
      details: error.message
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

// Enhanced WebSocket handler functions with better error handling and authentication
async function handleWebSocketConnection(request, env) {
  console.log('🔌 WebSocket connection attempt started');
  
  const url = new URL(request.url);
  const conversationId = url.searchParams.get('conversationId');
  const userId = url.searchParams.get('userId');
  const token = url.searchParams.get('token');
  const isGlobal = url.searchParams.get('global') === 'true';
  
  // Better parameter validation
  if (!userId) {
    console.error('❌ WebSocket connection failed: Missing userId parameter');
    return new Response('Missing required parameters: userId', { status: 400 });
  }

  console.log(`📋 WebSocket connection details:`, {
    conversationId,
    userId,
    isGlobal,
    hasToken: !!token,
    origin: request.headers.get('Origin'),
    userAgent: request.headers.get('User-Agent')
  });

  try {
    // Enhanced authentication verification with better error messages
    let authResult;
    if (token) {
      console.log('🔐 Verifying token authentication...');
      authResult = await verifyTokenAuth(token, env);
    } else {
      console.log('🍪 Verifying cookie/header authentication...');
      authResult = await verifyUserAuth(request, env);
    }
    
    if (!authResult.success) {
      console.error('❌ Authentication failed:', authResult.error);
      return new Response(`Authentication failed: ${authResult.error}`, { status: 401 });
    }
    
    if (authResult.userId !== parseInt(userId)) {
      console.error('❌ User ID mismatch:', { 
        expectedUserId: parseInt(userId), 
        authenticatedUserId: authResult.userId 
      });
      return new Response('User ID mismatch', { status: 401 });
    }

    console.log(`✅ Authentication successful for user ${authResult.userId} (${authResult.username})`);

    // For specific conversation connections, verify user access
    if (conversationId && !isGlobal) {
      console.log(`🔍 Verifying conversation access for conversation ${conversationId}`);
      
      try {
        const conversation = await env.DB.prepare(
          'SELECT buyer_id, seller_id FROM conversations WHERE id = ?'
        ).bind(conversationId).first();
        
        if (!conversation) {
          console.error(`❌ Conversation ${conversationId} not found`);
          return new Response('Conversation not found', { status: 404 });
        }
        
        if (conversation.buyer_id !== authResult.userId && conversation.seller_id !== authResult.userId) {
          console.error(`❌ User ${authResult.userId} not authorized for conversation ${conversationId}`);
          return new Response('Access denied to conversation', { status: 403 });
        }
        
        console.log(`✅ User ${authResult.userId} authorized for conversation ${conversationId}`);
      } catch (dbError) {
        console.error('❌ Database error during conversation verification:', dbError);
        return new Response('Database error during verification', { status: 500 });
      }
    }

    // Check if CHAT_ROOM binding exists
    if (!env.CHAT_ROOM) {
      console.error('❌ CHAT_ROOM Durable Object binding not found');
      return new Response('Chat service unavailable - missing binding', { status: 500 });
    }

    // Create a unique ID for the chat room with rate limiting
    const roomName = isGlobal ? `global-${authResult.userId}` : `conversation-${conversationId}`;
    console.log(`🏠 Creating/accessing chat room: ${roomName}`);
    
    try {
      const roomId = env.CHAT_ROOM.idFromName(roomName);
      const chatRoom = env.CHAT_ROOM.get(roomId);

      // Create enhanced request with proper headers and error context
      const enhancedRequest = new Request(request.url, {
        method: request.method,
        headers: {
          ...Object.fromEntries(request.headers.entries()),
          'X-User-ID': authResult.userId.toString(),
          'X-User-Name': authResult.username || 'User',
          'X-Rate-Limit': '30', // messages per minute
          'X-Connection-Time': Date.now().toString(),
          'X-Auth-Success': 'true',
          'X-Original-URL': request.url
        },
        body: request.body
      });

      console.log(`🚀 Forwarding WebSocket upgrade to Durable Object: ${roomName}`);
      
      // Forward the WebSocket upgrade to the Durable Object
      const response = await chatRoom.fetch(enhancedRequest);
      
      if (response.status === 101) {
        console.log(`✅ WebSocket upgrade successful for user ${authResult.userId} in room ${roomName}`);
      } else {
        console.error(`❌ Durable Object returned status ${response.status} for WebSocket upgrade`);
      }
      
      return response;
      
    } catch (roomError) {
      console.error('❌ Error creating/accessing chat room:', roomError);
      return new Response(`Chat room error: ${roomError.message}`, { status: 500 });
    }

  } catch (error) {
    console.error('❌ WebSocket connection error:', error);
    return new Response(`WebSocket connection failed: ${error.message}`, { status: 500 });
  }
}

// Get active users in a conversation
async function handleGetActiveUsers(conversationId, env, corsHeaders) {
  try {
    const roomId = env.CHAT_ROOM.idFromName(`conversation-${conversationId}`);
    const chatRoom = env.CHAT_ROOM.get(roomId);
    
    // Create a request to get active users
    const response = await chatRoom.fetch(new Request('https://internal/active-users', {
      method: 'GET'
    }));
    
    const activeUsers = await response.json();
    
    return new Response(JSON.stringify({ users: activeUsers }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: 'Failed to get active users' }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

// Handle typing indicators
async function handleTypingIndicator(conversationId, request, env, corsHeaders) {
  try {
    const user = await getUserFromSession(request, env);
    if (!user) {
      return new Response(JSON.stringify({ error: 'Authentication required' }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    const { isTyping } = await request.json();
    
    // Forward typing indicator to the Durable Object
    const roomId = env.CHAT_ROOM.idFromName(`conversation-${conversationId}`);
    const chatRoom = env.CHAT_ROOM.get(roomId);
    
    const typingRequest = new Request('https://internal/typing', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-User-ID': user.user_id.toString(),
        'X-User-Name': user.profile_name
      },
      body: JSON.stringify({ isTyping, conversationId })
    });
    
    await chatRoom.fetch(typingRequest);
    
    return new Response(JSON.stringify({ success: true }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  } catch (error) {
    console.error('Typing indicator error:', error);
    return new Response(JSON.stringify({ error: 'Failed to process typing indicator' }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

// Get unread message counts for all conversations
async function handleGetUnreadCounts(request, env, corsHeaders) {
  try {
    const user = await getUserFromSession(request, env);
    if (!user) {
      return new Response(JSON.stringify({ error: 'Authentication required' }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    // Get unread counts for all user's conversations
    const unreadCounts = await env.DB.prepare(`
      SELECT 
        c.id as conversation_id,
        COUNT(m.id) as unread_count
      FROM conversations c
      LEFT JOIN messages m ON c.id = m.conversation_id 
        AND m.sender_id != ? 
        AND m.is_read = 0
      WHERE c.buyer_id = ? OR c.seller_id = ?
      GROUP BY c.id
    `).bind(user.user_id, user.user_id, user.user_id).all();
    
    return new Response(JSON.stringify({ unreadCounts: unreadCounts.results || [] }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  } catch (error) {
    console.error('Get unread counts error:', error);
    return new Response(JSON.stringify({ error: 'Failed to get unread counts' }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

// Mark specific message as read (for read receipts)
async function handleMarkMessageRead(messageId, request, env, corsHeaders) {
  try {
    const user = await getUserFromSession(request, env);
    if (!user) {
      return new Response(JSON.stringify({ error: 'Authentication required' }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    // Verify user has access to this message
    const message = await env.DB.prepare(`
      SELECT m.*, c.buyer_id, c.seller_id 
      FROM messages m
      JOIN conversations c ON m.conversation_id = c.id
      WHERE m.id = ?
    `).bind(messageId).first();
    
    if (!message) {
      return new Response(JSON.stringify({ error: 'Message not found' }), {
        status: 404,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    if (message.buyer_id !== user.user_id && message.seller_id !== user.user_id) {
      return new Response(JSON.stringify({ error: 'Access denied' }), {
        status: 403,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    // Mark message as read if user is not the sender
    if (message.sender_id !== user.user_id) {
      await env.DB.prepare(
        'UPDATE messages SET is_read = 1, read_at = datetime("now") WHERE id = ?'
      ).bind(messageId).run();
      
      // Notify via WebSocket if available
      const roomId = env.CHAT_ROOM.idFromName(`conversation-${message.conversation_id}`);
      const chatRoom = env.CHAT_ROOM.get(roomId);
      
      const readReceiptRequest = new Request('https://internal/read-receipt', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-User-ID': user.user_id.toString()
        },
        body: JSON.stringify({ 
          messageId: messageId,
          conversationId: message.conversation_id,
          readBy: user.user_id 
        })
      });
      
      await chatRoom.fetch(readReceiptRequest);
    }
    
    return new Response(JSON.stringify({ success: true }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  } catch (error) {
    console.error('Mark message read error:', error);
    return new Response(JSON.stringify({ error: 'Failed to mark message as read' }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

// Enhanced auth verification for WebSocket connections with better error handling
async function verifyUserAuth(request, env) {
  try {
    console.log('🔍 Verifying user authentication...');
    
    // Check for session cookie or Authorization header
    const cookies = parseCookies(request.headers.get('Cookie') || '');
    const sessionToken = cookies.session || 
      request.headers.get('Authorization')?.replace('Bearer ', '');

    if (!sessionToken) {
      console.log('🚫 No session token found in cookies or Authorization header');
      return { success: false, error: 'No session token found' };
    }

    console.log('🔍 Session token found, verifying...');
    return await verifyTokenAuth(sessionToken, env);
  } catch (error) {
    console.error('💥 Auth verification error:', error);
    return { success: false, error: `Auth verification failed: ${error.message}` };
  }
}

// Enhanced token verification with better error handling
async function verifyTokenAuth(sessionToken, env) {
  try {
    console.log('🔐 Verifying session token...');
    
    // Check if database is available
    if (!env.DB) {
      console.error('❌ Database binding not available');
      return { success: false, error: 'Database unavailable' };
    }

    // Verify the session token with detailed error handling
    const session = await env.DB.prepare(`
      SELECT s.user_id, u.profile_name, u.email, u.is_verified
      FROM user_sessions s
      JOIN users u ON s.user_id = u.id
      WHERE s.session_token = ? AND s.expires_at > datetime('now')
    `).bind(sessionToken).first();

    if (!session) {
      console.log('🚫 Invalid or expired session token');
      return { success: false, error: 'Invalid or expired session' };
    }

    if (!session.is_verified) {
      console.log('🚫 User email not verified');
      return { success: false, error: 'Email not verified' };
    }

    console.log(`✅ Session verified for user ${session.user_id} (${session.profile_name})`);
    
    return {
      success: true,
      userId: session.user_id,
      username: session.profile_name,
      email: session.email,
      isVerified: session.is_verified === 1
    };
  } catch (error) {
    console.error('💥 Token verification error:', error);
    return { success: false, error: `Token verification failed: ${error.message}` };
  }
}

// Helper function to parse cookies
function parseCookies(cookieHeader) {
  const cookies = {};
  if (cookieHeader) {
    cookieHeader.split(';').forEach(cookie => {
      const [name, value] = cookie.trim().split('=');
      if (name && value) {
        cookies[name] = decodeURIComponent(value);
      }
    });
  }
  return cookies;
}
