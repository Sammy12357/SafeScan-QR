from __future__ import annotations

from dataclasses import dataclass
import re


FASTPEOPLESEARCH_OPTOUT_URL = "https://www.fastpeoplesearch.com/optout"
FASTPEOPLESEARCH_SELF_REQUEST_TEXT = "I am the subject of this request"


@dataclass(frozen=True)
class RemovalProfile:
    name: str
    address: str = ""
    city_state: str = ""
    phone: str = ""
    email: str = ""


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
        "iframe[title*='reCAPTCHA' i]",
        ".g-recaptcha",
        "text=/I'm not a robot/i",
    ]
    for selector in checks:
        try:
            if await page.locator(selector).first.count():
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
        "button:has-text('Continue')",
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


async def run_fastpeoplesearch_removal(
    profile: RemovalProfile,
    *,
    headless: bool = True,
    timeout_ms: int = 45_000,
) -> dict[str, str]:
    if not profile.name.strip():
        return {"status": "failed", "detail": "Name is required.", "targetUrl": FASTPEOPLESEARCH_OPTOUT_URL}
    if not profile.email.strip():
        return {"status": "failed", "detail": "Email is required.", "targetUrl": FASTPEOPLESEARCH_OPTOUT_URL}

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
            await page.goto(FASTPEOPLESEARCH_OPTOUT_URL, wait_until="domcontentloaded")
            selected_requester = await _select_requester_type(page)
            filled_first = await _fill_first_match(page, [
                "input[placeholder='John']",
                "input[placeholder*='First' i]",
                "input[name*='first' i]",
                "input[id*='first' i]",
                "input[aria-label*='first' i]",
            ], name["first"])
            filled_middle = await _fill_first_match(page, [
                "input[placeholder='Middle']",
                "input[placeholder*='Middle' i]",
                "input[name*='middle' i]",
                "input[id*='middle' i]",
                "input[aria-label*='middle' i]",
            ], name["middle"])
            filled_last = await _fill_first_match(page, [
                "input[placeholder='Doe']",
                "input[placeholder*='Last' i]",
                "input[name*='last' i]",
                "input[id*='last' i]",
                "input[aria-label*='last' i]",
            ], name["last"])
            filled_email = await _fill_first_match(page, [
                "input[type='email']",
                "input[placeholder*='@']",
                "input[placeholder*='Email' i]",
                "input[name*='email' i]",
                "input[id*='email' i]",
                "input[aria-label*='email' i]",
            ], profile.email.strip())
            checked_authorization = await _check_authorization(page)

            filled_summary = [
                f"requester={'yes' if selected_requester else 'no'}",
                f"first={'yes' if filled_first else 'no'}",
                f"middle={'yes' if filled_middle or not name['middle'] else 'no'}",
                f"last={'yes' if filled_last else 'no'}",
                f"email={'yes' if filled_email else 'no'}",
                f"authorization={'yes' if checked_authorization else 'no'}",
            ]
            if not (selected_requester and filled_first and filled_last and filled_email):
                return {
                    "status": "failed",
                    "detail": "FastPeopleSearch backend autofill could not complete required fields: " + ", ".join(filled_summary),
                    "targetUrl": page.url,
                }

            if await _captcha_present(page):
                return {
                    "status": "captcha_required",
                    "detail": "FastPeopleSearch backend autofilled required fields, but reCAPTCHA requires a human checkpoint before submission: " + ", ".join(filled_summary),
                    "targetUrl": page.url,
                }

            submitted = await _click_submit(page)
            if not submitted:
                return {
                    "status": "filled",
                    "detail": "FastPeopleSearch backend autofilled required fields, but no submit button was available: " + ", ".join(filled_summary),
                    "targetUrl": page.url,
                }

            try:
                await page.wait_for_load_state("networkidle", timeout=8_000)
            except PlaywrightTimeoutError:
                pass
            return {
                "status": "submitted",
                "detail": "FastPeopleSearch opt-out was submitted by backend automation. Check the confirmation email next: " + ", ".join(filled_summary),
                "targetUrl": page.url,
            }
        finally:
            await browser.close()
