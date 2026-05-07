const feed = document.querySelector(".activity-feed");
if (feed) {
  window.setInterval(() => {
    if (!document.hidden) window.location.reload();
  }, 30000);
}

document.querySelectorAll("form").forEach((form) => {
  form.addEventListener("submit", (event) => {
    const dangerous = form.querySelector("button[name='status'][value='disqualified'], button[name='outcome'][value='disqualified']");
    if (dangerous && !window.confirm("Confirm this admin action?")) {
      event.preventDefault();
    }
  });
});
