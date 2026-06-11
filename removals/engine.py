from __future__ import annotations

from dataclasses import dataclass
import re


@dataclass(frozen=True)
class RemovalProfile:
    name: str
    address: str = ""
    city_state: str = ""
    phone: str = ""
    email: str = ""


@dataclass(frozen=True)
class BrokerConfig:
    """Per-broker automation recipe.

    The generic runner leans on placeholder/name/id heuristics that work
    across most opt-out forms. These flags adjust the runner for each
    broker's quirks:

    - requester_type: the form has a "who are you" dropdown that must be set
      to the data subject before the request is valid.
    - authorization: the form has an "I am authorized / I confirm" checkbox.
    - record_based: the opt-out cannot be completed from name fields alone;
      the broker first needs the URL of the specific listing (the user must
      find and confirm their own record). The runner fills what it can but
      returns a `needs_profile_url` checkpoint instead of a false success.
    - email_verification: the broker emails a confirmation link after submit,
      so a `submitted` result still leaves a manual email step for the user.
    """

    id: str
    name: str
    optout_url: str
    requester_type: bool = False
    authorization: bool = False
    record_based: bool = False
    email_verification: bool = True


BROKER_CONFIGS: dict[str, BrokerConfig] = {
    "fastpeoplesearch": BrokerConfig(
        id="fastpeoplesearch",
        name="FastPeopleSearch",
        optout_url="https://www.fastpeoplesearch.com/optout",
        requester_type=True,
        authorization=True,
        record_based=False,
        email_verification=True,
    ),
    "thatsthem": BrokerConfig(
        id="thatsthem",
        name="Thatsthem",
        optout_url="https://thatsthem.com/optout",
        requester_type=False,
        authorization=True,
        record_based=False,
        email_verification=True,
    ),
    "truepeoplesearch": BrokerConfig(
        id="truepeoplesearch",
        name="TruePeopleSearch",
        optout_url="https://www.truepeoplesearch.com/removal",
        requester_type=False,
        authorization=True,
        record_based=True,
        email_verification=True,
    ),
    "spokeo": BrokerConfig(
        id="spokeo",
        name="Spokeo",
        optout_url="https://www.spokeo.com/optout",
        requester_type=False,
        authorization=False,
        record_based=True,
        email_verification=True,
    ),
    "nuwber": BrokerConfig(
        id="nuwber",
        name="Nuwber",
        optout_url="https://nuwber.com/removal/link",
        requester_type=False,
        authorization=False,
        record_based=True,
        email_verification=True,
    ),
    "beenverified": BrokerConfig(
        id="beenverified",
        name="BeenVerified",
        optout_url="https://www.beenverified.com/app/optout/search/",
        requester_type=False,
        authorization=False,
        record_based=True,
        email_verification=True,
    ),
    "whitepages": BrokerConfig(
        id="whitepages",
        name="Whitepages",
        optout_url="https://www.whitepages.com/suppression-requests",
        requester_type=False,
        authorization=False,
        record_based=True,
        email_verification=True,
    ),
    "radaris": BrokerConfig(
        id="radaris",
        name="Radaris",
        optout_url="https://radaris.com/control/privacy",
        requester_type=False,
        authorization=False,
        record_based=True,
        email_verification=True,
    ),
}


def supported_broker(broker_id: str) -> BrokerConfig | None:
    return BROKER_CONFIGS.get((broker_id or "").strip().lower())


def split_name(full_name: str) -> dict[str, str]:
    parts = [part.strip() for part in (full_name or "").replace(".", " ").split() if part.strip()]
    if not parts:
        return {"first": "", "middle": "", "last": ""}
    if len(parts) == 1:
        return {"first": parts[0], "middle": "", "last": ""}
    if len(parts) == 2:
        return {"first": parts[0], "middle": "", "last": parts[1]}
    return {"first": parts[0], "middle": " ".join(parts[1:-1]), "last": parts[-1]}


async def _fill_first_match(page, selectors: list[str], value: str) -> bool:
    if not value:
        return False
    for selector in selectors:
        locator = page.locator(selector).first
        try:
            if await locator.count() and await locator.is_visible():
                await locator.fill(value)
                return True
        except Exception:
            continue
    return False


async def _click_text_match(page, patterns: list[str]) -> bool:
    for pattern in patterns:
        try:
            locator = page.get_by_text(re.compile(pattern, re.IGNORECASE)).first
            if await locator.count() and await locator.is_visible():
                await locator.click()
                return True
        except Exception:
            continue
    return False


async def _select_requester_type(page) -> bool:
    select = page.locator("select").first
    try:
        if await select.count():
            options = await select.locator("option").evaluate_all(
                """options => options.map((option, index) => ({
                    index,
                    value: option.value || "",
                    text: option.textContent || ""
                }))"""
            )
            for option in options:
                text = (option.get("text") or "").strip().lower()
                value = (option.get("value") or "").strip()
                if value and (
                    "i am the subject" in text
                    or "subject of this request" in text
                    or text in {"self", "myself", "me"}
                ):
                    await select.select_option(value=value)
                    return True
            for option in options:
                text = (option.get("text") or "").strip().lower()
                value = (option.get("value") or "").strip()
                if value and "choose" not in text:
                    await select.select_option(value=value)
                    return True
            if len(options) > 1:
                await select.select_option(index=1)
                return True
    except Exception:
        pass

    return await _click_text_match(page, [
        r"i\s+am\s+the\s+subject\s+of\s+this\s+request",
        r"subject\s+of\s+this\s+request",
        r"\bmyself\b",
    ])


async def _check_authorization(page) -> bool:
    selectors = [
        "input[type='checkbox'][name*='author' i]",
        "input[type='checkbox'][id*='author' i]",
        "input[type='checkbox'][name*='confirm' i]",
        "input[type='checkbox'][name*='agree' i]",
        "input[type='checkbox']",
    ]
    for selector in selectors:
        locator = page.locator(selector).first
        try:
            if await locator.count() and await locator.is_visible():
                await locator.check()
                return True
        except Exception:
            continue
    return False


async def _captcha_present(page) -> bool:
    checks = [
        "iframe[src*='recaptcha']",
        "iframe[src*='hcaptcha']",
        "iframe[title*='reCAPTCHA' i]",
        "iframe[title*='hCaptcha' i]",
        "iframe[src*='challenges.cloudflare.com']",
        ".g-recaptcha",
        ".h-captcha",
        ".cf-turnstile",
        "text=/I'm not a robot/i",
    ]
    for selector in checks:
        try:
            if await page.locator(selector).first.count():
                return True
        except Exception:
            continue
    return False


async def _email_verification_notice(page) -> bool:
    patterns = [
        r"check\s+your\s+email",
        r"verification\s+email",
        r"confirm(ation)?\s+email",
        r"verify\s+your\s+email",
        r"we('|’)?ve?\s+sent",
        r"link\s+to\s+confirm",
    ]
    for pattern in patterns:
        try:
            locator = page.get_by_text(re.compile(pattern, re.IGNORECASE)).first
            if await locator.count() and await locator.is_visible():
                return True
        except Exception:
            continue
    return False


async def _click_submit(page) -> bool:
    selectors = [
        "button[type='submit']",
        "input[type='submit']",
        "button:has-text('Submit')",
        "input[value*='Submit' i]",
        "button:has-text('Send')",
        "button:has-text('Begin')",
        "button:has-text('Continue')",
        "button:has-text('Opt out')",
        "button:has-text('Remove')",
    ]
    for selector in selectors:
        locator = page.locator(selector).first
        try:
            if await locator.count() and await locator.is_visible():
                await locator.click()
                return True
        except Exception:
            continue
    return False


_FIRST_NAME_SELECTORS = [
    "input[placeholder='John']",
    "input[placeholder*='First' i]",
    "input[name*='first' i]",
    "input[id*='first' i]",
    "input[aria-label*='first' i]",
]
_MIDDLE_NAME_SELECTORS = [
    "input[placeholder='Middle']",
    "input[placeholder*='Middle' i]",
    "input[name*='middle' i]",
    "input[id*='middle' i]",
    "input[aria-label*='middle' i]",
]
_LAST_NAME_SELECTORS = [
    "input[placeholder='Doe']",
    "input[placeholder*='Last' i]",
    "input[name*='last' i]",
    "input[id*='last' i]",
    "input[aria-label*='last' i]",
]
_FULL_NAME_SELECTORS = [
    "input[name='name']",
    "input[placeholder*='Full name' i]",
    "input[aria-label*='Full name' i]",
    "input[name*='fullname' i]",
]
_EMAIL_SELECTORS = [
    "input[type='email']",
    "input[placeholder*='@']",
    "input[placeholder*='Email' i]",
    "input[name*='email' i]",
    "input[id*='email' i]",
    "input[aria-label*='email' i]",
]
_PHONE_SELECTORS = [
    "input[type='tel']",
    "input[placeholder*='Phone' i]",
    "input[name*='phone' i]",
    "input[id*='phone' i]",
    "input[aria-label*='phone' i]",
]
_ADDRESS_SELECTORS = [
    "input[placeholder*='Street' i]",
    "input[placeholder*='Address' i]",
    "input[name*='address' i]",
    "input[name*='street' i]",
    "input[id*='address' i]",
    "input[aria-label*='address' i]",
]
_CITY_STATE_SELECTORS = [
    "input[placeholder*='City' i]",
    "input[placeholder*='State' i]",
    "input[name*='citystate' i]",
    "input[name*='city' i]",
    "input[id*='city' i]",
    "input[aria-label*='city' i]",
]


async def run_broker_removal(
    broker_id: str,
    profile: RemovalProfile,
    *,
    headless: bool = True,
    timeout_ms: int = 45_000,
) -> dict[str, str]:
    config = supported_broker(broker_id)
    if config is None:
        return {
            "status": "unavailable",
            "detail": f"Backend automation is not configured for '{broker_id}'.",
            "targetUrl": "",
        }

    if not profile.name.strip():
        return {"status": "failed", "detail": "Name is required.", "targetUrl": config.optout_url}
    if not profile.email.strip():
        return {"status": "failed", "detail": "Email is required.", "targetUrl": config.optout_url}

    try:
        from playwright.async_api import TimeoutError as PlaywrightTimeoutError
        from playwright.async_api import async_playwright
    except ImportError as exc:
        raise RuntimeError("Playwright is not installed in this environment.") from exc

    name = split_name(profile.name)

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(
            headless=headless,
            args=["--no-sandbox", "--disable-dev-shm-usage"],
        )
        page = await browser.new_page(
            viewport={"width": 1440, "height": 1200},
            user_agent=(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
            ),
        )
        page.set_default_timeout(timeout_ms)
        try:
            await page.goto(config.optout_url, wait_until="domcontentloaded")

            selected_requester = True
            if config.requester_type:
                selected_requester = await _select_requester_type(page)

            filled_first = await _fill_first_match(page, _FIRST_NAME_SELECTORS, name["first"])
            await _fill_first_match(page, _MIDDLE_NAME_SELECTORS, name["middle"])
            filled_last = await _fill_first_match(page, _LAST_NAME_SELECTORS, name["last"])
            # Some brokers use a single "Full name" field instead of split parts.
            filled_fullname = False
            if not (filled_first and filled_last):
                filled_fullname = await _fill_first_match(page, _FULL_NAME_SELECTORS, profile.name.strip())
            filled_email = await _fill_first_match(page, _EMAIL_SELECTORS, profile.email.strip())
            filled_phone = await _fill_first_match(page, _PHONE_SELECTORS, profile.phone.strip())
            filled_address = await _fill_first_match(page, _ADDRESS_SELECTORS, profile.address.strip())
            filled_city_state = await _fill_first_match(page, _CITY_STATE_SELECTORS, profile.city_state.strip())

            checked_authorization = True
            if config.authorization:
                checked_authorization = await _check_authorization(page)

            has_name = filled_first or filled_fullname
            filled_summary = ", ".join([
                f"requester={'yes' if selected_requester else 'no'}",
                f"name={'yes' if has_name else 'no'}",
                f"email={'yes' if filled_email else 'no'}",
                f"phone={'yes' if filled_phone else 'na'}",
                f"address={'yes' if filled_address else 'na'}",
                f"citystate={'yes' if filled_city_state else 'na'}",
                f"authorization={'yes' if checked_authorization else 'na'}",
            ])

            # Record-based brokers (Spokeo, Nuwber, BeenVerified, Whitepages,
            # Radaris, TruePeopleSearch) remove a *specific listing*. Even when
            # the opt-out page has a name field, it is only a search box - the
            # actual removal still needs the user to pick which result is them
            # and confirm. Because the backend browser is headless and
            # server-side, the user can't see that search, so we never claim a
            # false submission: we report a profile-URL checkpoint and let them
            # finish in their own browser via Search -> Opt out.
            if config.record_based:
                return {
                    "status": "needs_profile_url",
                    "detail": (
                        f"{config.name} removes by specific listing. Use Search to find your "
                        f"record in your browser, open it, then Opt out and confirm by email. "
                        f"({filled_summary})"
                    ),
                    "targetUrl": page.url,
                }

            if not (has_name and filled_email):
                return {
                    "status": "failed",
                    "detail": f"{config.name} autofill could not complete required fields: {filled_summary}",
                    "targetUrl": page.url,
                }

            if await _captcha_present(page):
                return {
                    "status": "captcha_required",
                    "detail": (
                        f"{config.name} autofilled the required fields, but it shows a CAPTCHA "
                        f"the backend browser can't clear. Click Finish in browser to open the "
                        f"broker page with your details copied, then solve the CAPTCHA and submit. "
                        f"({filled_summary})"
                    ),
                    "targetUrl": page.url,
                }

            submitted = await _click_submit(page)
            if not submitted:
                return {
                    "status": "filled",
                    "detail": f"{config.name} autofilled the required fields, but no submit button was available: {filled_summary}",
                    "targetUrl": page.url,
                }

            try:
                await page.wait_for_load_state("networkidle", timeout=8_000)
            except PlaywrightTimeoutError:
                pass

            if config.email_verification or await _email_verification_notice(page):
                return {
                    "status": "email_required",
                    "detail": (
                        f"{config.name} opt-out was submitted. Open the confirmation email "
                        f"{config.name} sends and click the verification link to finish. ({filled_summary})"
                    ),
                    "targetUrl": page.url,
                }

            return {
                "status": "submitted",
                "detail": f"{config.name} opt-out was submitted by backend automation. ({filled_summary})",
                "targetUrl": page.url,
            }
        except PlaywrightTimeoutError as exc:
            return {
                "status": "failed",
                "detail": f"{config.name} autofill timed out at {page.url}: {str(exc)[:320]}",
                "targetUrl": page.url,
            }
        except Exception as exc:
            return {
                "status": "failed",
                "detail": f"{config.name} autofill stopped at {page.url}: {type(exc).__name__}: {str(exc)[:320]}",
                "targetUrl": page.url,
            }
        finally:
            await browser.close()
