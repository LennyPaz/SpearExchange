import bcrypt from 'bcryptjs';

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
        'GET /api/listings',
        'POST /api/listings',
        'GET /api/listings/:id',
        'PUT /api/listings/:id',
        'DELETE /api/listings/:id',
        'GET /api/messages',
        'POST /api/messages',
        'POST /api/favorites/:id',
        'DELETE /api/favorites/:id',
		'POST /api/forgot-password',
        'POST /api/reset-password' 
      ]
    }), {
      headers: { 'Content-Type': 'application/json' }
    });
  },
};

async function handleAPI(request, env, url) {
  const corsHeaders = {
    'Access-Control-Allow-Origin': 'https://lennypaz.github.io',
	'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
	'Access-Control-Allow-Headers': 'Content-Type, Authorization',
	'Access-Control-Allow-Credentials': 'true'
  };

  if (request.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
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

    // Messages endpoints
    if (url.pathname === '/api/messages' && request.method === 'GET') {
      return handleGetMessages(request, env, corsHeaders);
    }

    if (url.pathname === '/api/messages' && request.method === 'POST') {
      return handleSendMessage(request, env, corsHeaders);
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

// Helper function to get user from session
async function getUserFromSession(request, env) {
  const cookieHeader = request.headers.get('Cookie');
  if (!cookieHeader) return null;
  
  const sessionToken = cookieHeader
    .split(';')
    .find(cookie => cookie.trim().startsWith('session='))
    ?.split('=')[1];
  
  if (!sessionToken) return null;
  
  const session = await env.DB.prepare(
    'SELECT s.user_id, u.email, u.profile_name FROM user_sessions s JOIN users u ON s.user_id = u.id WHERE s.session_token = ? AND s.expires_at > datetime("now")'
  ).bind(sessionToken).first();
  
  return session;
}

// Authentication functions
async function verifyCaptcha(token, env) {
  try {
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
    const baseUrl = env.PRODUCTION_URL || 'https://spear-exchange.lenny-paz123.workers.dev';
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
      return new Response(`
        <!DOCTYPE html>
        <html><head><meta http-equiv="refresh" content="0;url=https://lennypaz.github.io/SpearExchange/verify/?status=invalid&message=Missing verification token"></head></html>
      `, { headers: { 'Content-Type': 'text/html' } });
    }
    
    const user = await env.DB.prepare(
      'SELECT id, email, is_verified FROM users WHERE verification_token = ?'
    ).bind(token).first();
    
    if (!user) {
      return new Response(`
        <!DOCTYPE html>
        <html><head><meta http-equiv="refresh" content="0;url=https://lennypaz.github.io/SpearExchange/verify/?status=expired&message=This verification link is invalid or has expired"></head></html>
      `, { headers: { 'Content-Type': 'text/html' } });
    }
    
    if (user.is_verified) {
      return new Response(`
        <!DOCTYPE html>
        <html><head><meta http-equiv="refresh" content="0;url=https://lennypaz.github.io/SpearExchange/verify/?status=already_verified&message=Your email is already verified"></head></html>
      `, { headers: { 'Content-Type': 'text/html' } });
    }
    
    await env.DB.prepare(
      'UPDATE users SET is_verified = 1, verification_token = NULL WHERE id = ?'
    ).bind(user.id).run();
    
    return new Response(`
      <!DOCTYPE html>
      <html><head><meta http-equiv="refresh" content="0;url=https://lennypaz.github.io/SpearExchange/verify/?status=success&message=Your email has been verified successfully!"></head></html>
    `, { headers: { 'Content-Type': 'text/html' } });
    
  } catch (error) {
    console.error('Email verification error:', error);
    return new Response(`
      <!DOCTYPE html>
      <html><head><meta http-equiv="refresh" content="0;url=https://lennypaz.github.io/SpearExchange/verify/?status=error&message=An error occurred during verification"></head></html>
    `, { headers: { 'Content-Type': 'text/html' } });
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
      }
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
    const category = url.searchParams.get('category');
    const search = url.searchParams.get('search');
    const limit = parseInt(url.searchParams.get('limit')) || 20;
    const offset = parseInt(url.searchParams.get('offset')) || 0;
    
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
    
    if (search) {
      query += ' AND (l.title LIKE ? OR l.description LIKE ?)';
      params.push(`%${search}%`, `%${search}%`);
    }
    
    query += ' ORDER BY l.created_at DESC LIMIT ? OFFSET ?';
    params.push(limit, offset);
    
    const listings = await env.DB.prepare(query).bind(...params).all();
    
    return new Response(JSON.stringify({ 
      listings: listings.results || [],
      count: listings.results?.length || 0
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    console.error('Get listings error:', error);
    return new Response(JSON.stringify({ 
      error: 'Failed to fetch listings' 
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
    
    const { title, description, price, category, imageUrls, location } = await request.json();
    
    if (!title || !description || !price || !category) {
      return new Response(JSON.stringify({ error: 'Title, description, price, and category are required' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    const result = await env.DB.prepare(
      'INSERT INTO listings (user_id, title, description, price, category, image_urls, location) VALUES (?, ?, ?, ?, ?, ?, ?)'
    ).bind(
      user.user_id, 
      title, 
      description, 
      parseFloat(price), 
      category, 
      JSON.stringify(imageUrls || []), 
      location || ''
    ).run();
    
    return new Response(JSON.stringify({ 
      message: 'Listing created successfully',
      listingId: result.meta.last_row_id
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
      SELECT l.*, u.profile_name as seller_name, u.email as seller_email, u.phone_number as seller_phone
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
    
    // Parse image URLs
    if (listing.image_urls) {
      try {
        listing.image_urls = JSON.parse(listing.image_urls);
      } catch (e) {
        listing.image_urls = [];
      }
    }
    
    return new Response(JSON.stringify({ listing }), {
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
      'SELECT user_id FROM listings WHERE id = ?'
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
    
    const { title, description, price, category, imageUrls, location, status } = await request.json();
    
    await env.DB.prepare(`
      UPDATE listings 
      SET title = ?, description = ?, price = ?, category = ?, image_urls = ?, location = ?, status = ?, updated_at = datetime('now')
      WHERE id = ?
    `).bind(
      title || listing.title,
      description || listing.description,
      price !== undefined ? parseFloat(price) : listing.price,
      category || listing.category,
      JSON.stringify(imageUrls || []),
      location || listing.location,
      status || listing.status,
      listingId
    ).run();
    
    return new Response(JSON.stringify({ 
      message: 'Listing updated successfully' 
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

// Messages functions
async function handleGetMessages(request, env, corsHeaders) {
  try {
    const user = await getUserFromSession(request, env);
    if (!user) {
      return new Response(JSON.stringify({ error: 'Authentication required' }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    const url = new URL(request.url);
    const listingId = url.searchParams.get('listing_id');
    
    let query = `
      SELECT m.*, 
             sender.profile_name as sender_name,
             receiver.profile_name as receiver_name,
             l.title as listing_title
      FROM messages m
      JOIN users sender ON m.sender_id = sender.id
      JOIN users receiver ON m.receiver_id = receiver.id
      JOIN listings l ON m.listing_id = l.id
      WHERE (m.sender_id = ? OR m.receiver_id = ?)
    `;
    const params = [user.user_id, user.user_id];
    
    if (listingId) {
      query += ' AND m.listing_id = ?';
      params.push(listingId);
    }
    
    query += ' ORDER BY m.created_at DESC';
    
    const messages = await env.DB.prepare(query).bind(...params).all();
    
    return new Response(JSON.stringify({ 
      messages: messages.results || []
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    console.error('Get messages error:', error);
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
    
    const { listingId, receiverId, message } = await request.json();
    
    if (!listingId || !receiverId || !message) {
      return new Response(JSON.stringify({ error: 'Listing ID, receiver ID, and message are required' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    // Verify listing exists
    const listing = await env.DB.prepare(
      'SELECT id FROM listings WHERE id = ? AND status = "active"'
    ).bind(listingId).first();
    
    if (!listing) {
      return new Response(JSON.stringify({ error: 'Listing not found or no longer active' }), {
        status: 404,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    // Verify receiver exists
    const receiver = await env.DB.prepare(
      'SELECT id FROM users WHERE id = ?'
    ).bind(receiverId).first();
    
    if (!receiver) {
      return new Response(JSON.stringify({ error: 'Receiver not found' }), {
        status: 404,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    
    const result = await env.DB.prepare(
      'INSERT INTO messages (listing_id, sender_id, receiver_id, message) VALUES (?, ?, ?, ?)'
    ).bind(listingId, user.user_id, receiverId, message).run();
    
    return new Response(JSON.stringify({ 
      message: 'Message sent successfully',
      messageId: result.meta.last_row_id
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
      favorites: favorites.results || []
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
      return new Response(`
        <!DOCTYPE html>
        <html><head><meta http-equiv="refresh" content="0;url=https://lennypaz.github.io/SpearExchange/reset-password/?status=invalid&message=Missing reset token"></head></html>
      `, { headers: { 'Content-Type': 'text/html' } });
    }
    
    const user = await env.DB.prepare(
      'SELECT id, email, reset_token_expires FROM users WHERE reset_token = ?'
    ).bind(token).first();
    
    if (!user) {
      return new Response(`
        <!DOCTYPE html>
        <html><head><meta http-equiv="refresh" content="0;url=https://lennypaz.github.io/SpearExchange/reset-password/?status=invalid&message=Invalid or expired reset token"></head></html>
      `, { headers: { 'Content-Type': 'text/html' } });
    }
    
    // Check if token is expired
    const now = new Date();
    const expiresAt = new Date(user.reset_token_expires);
    
    if (now > expiresAt) {
      // Clean up expired token
      await env.DB.prepare(
        'UPDATE users SET reset_token = NULL, reset_token_expires = NULL WHERE id = ?'
      ).bind(user.id).run();
      
      return new Response(`
        <!DOCTYPE html>
        <html><head><meta http-equiv="refresh" content="0;url=https://lennypaz.github.io/SpearExchange/reset-password/?status=expired&message=Reset token has expired. Please request a new one."></head></html>
      `, { headers: { 'Content-Type': 'text/html' } });
    }
    
    // Token is valid, redirect to reset form with token
    return new Response(`
      <!DOCTYPE html>
      <html><head><meta http-equiv="refresh" content="0;url=https://lennypaz.github.io/SpearExchange/reset-password/?token=${token}&email=${encodeURIComponent(user.email)}"></head></html>
    `, { headers: { 'Content-Type': 'text/html' } });
    
  } catch (error) {
    console.error('Reset token verification error:', error);
    return new Response(`
      <!DOCTYPE html>
      <html><head><meta http-equiv="refresh" content="0;url=https://lennypaz.github.io/SpearExchange/reset-password/?status=error&message=An error occurred during verification"></head></html>
    `, { headers: { 'Content-Type': 'text/html' } });
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
    const baseUrl = env.PRODUCTION_URL || 'https://spear-exchange.lenny-paz123.workers.dev';
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
