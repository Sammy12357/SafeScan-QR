# Age gate implementation notes

This is an engineering control, not proof of age. The web form asks for birth year. It asks whether the birthday has already occurred this calendar year only for the cutoff birth year, when that answer could change eligibility. Without JavaScript the web form shows both questions. The server makes the decision and retains neither answer; when the birthday answer is omitted outside the cutoff year, it uses the younger possible age. The current account minimum is **16 globally** until a reviewed jurisdiction policy exists; browser language and client-supplied locale do not set the threshold. Adult-only payment, wallet, rewards, token and Go Ghost paths require a separate **18+ attestation**.

## Account sign-in

- Google web and Google/Auth0 mobile ID tokens are verified first. Before user creation, fraud processing or session issuance, `hackabull/age_gate.py` checks account eligibility bound to the verified identity.
- An unconfirmed account receives a 10-minute, one-use ticket. Web stores it in a Secure, HttpOnly, SameSite=Lax cookie; mobile receives it in a 202 JSON response. Minimal verified claims are temporarily stored in `pending_age_signins` and deleted on decision or lazily after expiration. A denied identity is represented only by a salted HMAC for a 24-hour retry hold.
- The old email-keyed `age_confirmations` rows do not authorize access. Existing session and remember-me resolution joins to `age_eligibility`, so existing users must complete the new age step at their next sign-in.
- A different verified provider subject cannot take over an existing account solely by presenting the same email. Such a legacy account needs an explicit, separately reviewed identity-linking recovery path.
- Local password/demo routes are disabled in production; they grant eligibility only in development to preserve developer fixtures. This exception must never be enabled in production.

## Mobile protocol

`POST /auth/verify` remains `200 {session,user}` for an eligible account. Otherwise it returns `202 {ageConfirmationRequired:true,ageTicket,minimumAge:16,expiresInSeconds:600}` and no session. The client sends `POST /auth/confirm-age/mobile` with `{ageTicket,birthYear,birthdayThisYear}` where `birthdayThisYear` is `"yes"` or `"no"`. A successful response is the original `200 {session,user}` shape. The ticket is single-use and expires in 10 minutes.

A protected API returns `403 {ageConfirmationRequired:true,ageTicket,minimumAge:18,expiresInSeconds:600}`. The client keeps its Bearer session and posts `{ageTicket,birthYear,birthdayThisYear,adultAttestation:true}` to `/auth/confirm-adult/mobile`. A successful response is `200 {adultConfirmed:true}`; retry the original API call afterward. Underage or false attestation returns 403 and consumes the ticket; expired, reused or wrong-account tickets return 410. The client should not persist the age inputs or ticket after completion.

The web adult form uses the same server-owned challenge and records an account attestation or issues a 24-hour guest token. Existing payment activation still requires its independent webhook security fix; visiting a payment success page is not payment proof.

## Release dependencies and limits

- Ship the mobile 202 and 403 handling before enabling this backend in production. No Auth0 tenant setting is required for the age flow.
- Confirm that production `PRIVACY_HASH_SALT` is set to a stable, private random value before rollout; the development fallback is not suitable for a production privacy hash.
- This control gates account and listed adult features. Guest QR analysis remains public. Self-reported answers can be false; this implementation does not verify an identity document or calculate jurisdiction from an IP address.
- Phase 2 can require explicit Terms/Privacy acceptance before `finish_verified_sign_in`; the pending identity stays server-side until all prerequisites are met.
- The published Terms and Privacy text in `hackabull/admin_data.py` still describes a 13+ global / 16+ EU rule. That conflicts with the implemented 16+ global account rule. Correct it through the versioned legal-document workflow and counsel review; do not treat the age-form copy change as a Terms or Privacy update.
