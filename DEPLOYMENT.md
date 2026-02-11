# Production Deployment Guide

This guide covers deploying the ZK-ID portal and API server to production.

## Architecture

- **Portal** (Static) → GitHub Pages
- **API Server** → Railway (or Render/Vercel)
- **Communication** → Portal calls API via CORS

## Step 1: Deploy API Server to Railway

### A. Create Railway Account

1. Go to https://railway.app
2. Sign up with GitHub
3. Click **New Project** → **Deploy from GitHub repo**
4. Select **star7js/zk-id**

### B. Configure the Service

1. **Root Directory**: Leave as `/` (uses `railway.json`)
2. **Environment Variables**: None required for basic setup
3. Railway will automatically:
   - Run `npm ci && npm run build:core`
   - Start with `npm start --workspace=@zk-id/example-web-app`
   - Expose the service on a public URL

### C. Get Your API URL

After deployment completes (~2-3 minutes):
1. Click on your service
2. Go to **Settings** → **Networking**
3. Copy the **Public URL** (e.g., `https://zk-id-production.up.railway.app`)

## Step 2: Configure GitHub Pages with API URL

### A. Add API URL as GitHub Secret

1. Go to your GitHub repo: https://github.com/star7js/zk-id
2. Navigate to **Settings** → **Secrets and variables** → **Actions**
3. Click **New repository secret**
4. Name: `API_URL`
5. Value: Your Railway URL (e.g., `https://zk-id-production.up.railway.app`)
6. Click **Add secret**

### B. Enable GitHub Pages

1. Go to **Settings** → **Pages**
2. Under **Source**, select **GitHub Actions**
3. Save

### C. Deploy Portal

The portal will automatically deploy when you push changes. To manually trigger:
1. Go to **Actions** tab
2. Select **Deploy Portal to GitHub Pages**
3. Click **Run workflow** → **Run workflow**

## Step 3: Verify Deployment

Once both deployments complete:

1. **Portal**: Visit https://star7js.github.io/zk-id/
2. **Quick Start**: https://star7js.github.io/zk-id/quick-start
3. **Playground**: https://star7js.github.io/zk-id/playground

Test the interactive features:
1. Issue a credential
2. Generate a proof (should work with deployed API)
3. Verify the proof

## Alternative: Deploy to Render

If you prefer Render over Railway:

1. Create account at https://render.com
2. **New** → **Web Service**
3. Connect your GitHub repo
4. Configure:
   - **Name**: zk-id-api
   - **Root Directory**: `examples/web-app`
   - **Build Command**: `cd ../.. && npm ci && npm run build:core`
   - **Start Command**: `npm start`
   - **Environment**: Node
5. Click **Create Web Service**

Then follow the same GitHub Pages configuration steps above.

## Alternative: Deploy to Vercel

⚠️ **Warning**: Vercel has a 50MB function size limit. Your circuit files may exceed this.

If your circuit files are small enough:

1. Install Vercel CLI: `npm i -g vercel`
2. Navigate to `examples/web-app`
3. Run: `vercel --prod`
4. Use the deployment URL for `API_URL` secret

## Monitoring & Maintenance

### Railway Dashboard

- Monitor logs in real-time
- View resource usage
- Restart service if needed

### GitHub Actions

- Check deployment status in **Actions** tab
- View build logs for debugging
- Portal rebuilds automatically on changes

### CORS Configuration

The API server is configured to accept requests from:
- `http://localhost:4321` (development)
- `https://star7js.github.io` (production)

To add more origins, edit `examples/web-app/src/server.ts`:

```typescript
const allowedOrigins = [
  'http://localhost:4321',
  'https://star7js.github.io',
  'https://your-custom-domain.com', // Add here
];
```

## Cost Estimates

- **GitHub Pages**: Free
- **Railway**: Free tier (500 hours/month, sufficient for demo)
- **Render**: Free tier with limitations
- **Total**: $0/month for demo usage

## Troubleshooting

### Portal Shows "Failed to fetch"

- Check if API server is running in Railway
- Verify `API_URL` secret is set correctly
- Check CORS configuration in server.ts

### Circuit Files Not Loading

- Ensure Railway has enough disk space
- Verify `/circuits` path is accessible
- Check Railway logs for 404 errors

### Build Failures

- Check Node.js version (requires 18+)
- Verify all dependencies install correctly
- Review build logs in GitHub Actions or Railway

## Security Notes

- Circuit artifacts are served publicly
- API has basic rate limiting
- No authentication required for demo
- For production use, add proper authentication
