'use strict';
document.querySelectorAll('form[data-confirm]').forEach(form => {
  form.addEventListener('submit', event => {
    if (!window.confirm(form.dataset.confirm)) event.preventDefault();
  });
});
document.getElementById('download-profile')?.addEventListener('click', () => {
  const text = document.getElementById('client-config').value;
  const url = URL.createObjectURL(new Blob([text], {type: 'text/plain'}));
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = 'wireguard-client.conf';
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});
