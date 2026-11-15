/* Move keyboard focus to the first server-rejected field after a form POST.
   The marker is rendered only when the server returns a validation error. */
(function () {
  function focusServerError() {
    const summary = document.querySelector("[data-server-error-focus]");
    if (!summary) return;

    const invalid = Array.from(document.querySelectorAll('[aria-invalid="true"]')).find((field) =>
      !field.disabled && !field.closest("[hidden], [inert]") && field.getClientRects().length > 0
    );
    const target = invalid || summary;
    if (target === summary && !summary.hasAttribute("tabindex")) summary.tabIndex = -1;
    target.focus();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", focusServerError, { once: true });
  } else {
    focusServerError();
  }
})();
