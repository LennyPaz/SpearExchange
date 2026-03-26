# Spear Exchange - Development Environment Setup

## Prerequisites
- Node.js (v18 or higher)
- npm
- Git

## Setup Steps

### 1. Download and Setup Project
1. Download all files from Google Drive
2. Extract to a folder (e.g., `spear-exchange-dev`)
3. Open terminal in that folder

### 2. Install Dependencies
```bash
npm install
3. Authenticate with Cloudflare
bashnpx wrangler auth login
Use the provided Cloudflare credentials
4. Deploy to Development Environment
bashnpx wrangler deploy --env dev
5. Test Development Database
bashnpx wrangler d1 execute spear-exchange-dev --remote --command "SELECT COUNT(*) FROM listings;"
Should return 4 listings
6. Run Locally (Optional)
bashnpx wrangler dev --env dev
Development Commands
Database Operations
bash# View all listings
npx wrangler d1 execute spear-exchange-dev --remote --command "SELECT * FROM listings;"

# Add test listing
npx wrangler d1 execute spear-exchange-dev --remote --command "INSERT INTO listings (user_id, title, description, price, category, status) VALUES (1, 'Test Item', 'Test description', 25.00, 'electronics', 'active');"

# Clear test data
npx wrangler d1 execute spear-exchange-dev --remote --command "DELETE FROM listings WHERE user_id = 1;"
Deployment
bash# Deploy changes to dev environment
npx wrangler deploy --env dev

# Check deployment status
npx wrangler deployments list --env dev
Environment Details

Dev Database: spear-exchange-dev
Dev Worker URL: https://spear-exchange-dev.[account].workers.dev
R2 Bucket: spear-exchange-images (shared)

Development Users

devuser1@fsu.edu (ID: 1)
devuser2@fsu.edu (ID: 2)
testuser@fsu.edu (ID: 3)

Password: Use the signup flow to create your own test accounts
Important Notes

Always use --env dev for development commands
Your changes won't affect the production database
Images are stored in shared R2 bucket (organized by user ID)