# OpenID4VP Demo TODO

This is a placeholder for the full OpenID4VP demo. The core implementation is complete in the SDK packages.

## Completed

- ✅ OpenID4VPVerifier class in @zk-id/sdk
- ✅ OpenID4VPWallet class in @zk-id/sdk
- ✅ Reference issuer server
- ✅ Documentation (docs/OPENID4VP.md)
- ✅ Verifier server template (src/verifier.ts)

## To Complete

### High Priority

- [ ] Browser wallet UI (index.html + client.ts)
- [ ] Integration with reference issuer server
- [ ] QR code scanning for mobile
- [ ] End-to-end flow test

### Medium Priority

- [ ] Styling and UX improvements
- [ ] Error handling and user feedback
- [ ] State persistence in browser
- [ ] Multiple credential support

### Low Priority

- [ ] Mobile wallet app example
- [ ] Deep link handling
- [ ] Verifier discovery
- [ ] Request by reference support

## How to Complete

1. **Create index.html**: Browser-based wallet simulator
   - Shows authorization request details
   - Generates presentation using OpenID4VPWallet
   - Displays verification result

2. **Create client.ts**: Wallet logic

   ```typescript
   import { OpenID4VPWallet, IndexedDBCredentialStore } from '@zk-id/sdk';

   const wallet = new OpenID4VPWallet({
     store: new IndexedDBCredentialStore(),
   });

   // Fetch auth request from verifier
   // Generate presentation
   // Submit to callback URL
   ```

3. **Test end-to-end**:
   - Start issuer server (port 3001)
   - Start verifier server (port 3002)
   - Open browser wallet (port 3000)
   - Issue credential → Request verification → Generate proof → Verify

## Alternative: Extend Existing Web App

The existing `examples/web-app` could be extended with OpenID4VP support instead of creating a new demo. This would involve:

1. Adding OpenID4VP endpoints to server.ts
2. Adding OpenID4VP wallet mode to the UI
3. Updating README with OpenID4VP instructions

This might be preferable as it consolidates the demos and shows both direct integration and standards-compliant integration in one place.
