// Small progressive enhancements. The app works without JavaScript.
document.addEventListener("submit", (e) => {
  const form = e.target;
  if (form instanceof HTMLFormElement && form.classList.contains("js-confirm")) {
    if (!window.confirm(form.dataset.confirm || "Are you sure?")) e.preventDefault();
  }
});
