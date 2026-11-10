// Tiny progressive enhancement: confirm dialogs for buttons/forms marked data-confirm.
document.addEventListener("submit", function (ev) {
  var msg = ev.target.getAttribute("data-confirm");
  if (msg && !window.confirm(msg)) { ev.preventDefault(); }
});
