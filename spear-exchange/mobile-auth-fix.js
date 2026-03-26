// Mobile Authentication Fix
// Add this to your login page and any page that checks authentication

// Helper function to detect mobile
function isMobile() {
    return /Android|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent);
}

// Enhanced fetch function that handles both cookies and tokens
async function authenticatedFetch(url, options = {}) {
    const sessionToken = localStorage.getItem('sessionToken');
    
    // Default options
    const defaultOptions = {
        credentials: 'include',
        headers: {
            'Content-Type': 'application/json',
            ...options.headers
        }
    };
    
    // Add Authorization header for mobile
    if (isMobile() && sessionToken) {
        defaultOptions.headers['Authorization'] = `Bearer ${sessionToken}`;
    }
    
    return fetch(url, { ...defaultOptions, ...options });
}

// Update your login function to store the token
async function enhancedLogin(email, password) {
    try {
        const response = await fetch(`${API_BASE_URL}/api/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify({
                email: email,
                password: password
            })
        });

        const data = await response.json();

        if (response.ok) {
            // Store user info
            if (data.user) {
                localStorage.setItem('user', JSON.stringify(data.user));
            }
            
            // Store session token for mobile
            if (data.sessionToken) {
                localStorage.setItem('sessionToken', data.sessionToken);
            }
            
            return { success: true, data };
        } else {
            return { success: false, error: data.error, requiresVerification: data.requiresVerification };
        }
    } catch (error) {
        console.error('Login error:', error);
        return { success: false, error: 'Network error. Please check your connection and try again.' };
    }
}

// Enhanced auth check function
async function enhancedCheckAuth() {
    try {
        const response = await authenticatedFetch(`${API_BASE_URL}/api/me`);
        
        if (response.ok) {
            const data = await response.json();
            return { success: true, user: data.user };
        } else {
            // Clear stored credentials on auth failure
            localStorage.removeItem('user');
            localStorage.removeItem('sessionToken');
            return { success: false };
        }
    } catch (error) {
        console.error('Auth check failed:', error);
        localStorage.removeItem('user');
        localStorage.removeItem('sessionToken');
        return { success: false };
    }
}

// Enhanced logout function
async function enhancedLogout() {
    try {
        await authenticatedFetch(`${API_BASE_URL}/api/logout`, {
            method: 'POST'
        });
    } catch (error) {
        console.error('Logout error:', error);
    } finally {
        // Always clear local storage
        localStorage.removeItem('user');
        localStorage.removeItem('sessionToken');
        window.location.href = '../login';
    }
}
