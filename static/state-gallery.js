(function () {
  'use strict';
  var demo = document.getElementById('statesDemo');
  if (!demo || !window.UIStates) return;
  var loading = null;
  UIStates.empty(demo, { title: 'No saved items', body: 'Create one to see it here.', actionLabel: 'Start scanning', actionHref: '/#scanner' });
  document.querySelectorAll('[data-demo]').forEach(function (button) {
    button.addEventListener('click', function () {
      if (loading) loading.cancel();
      switch (button.getAttribute('data-demo')) {
        case 'empty':
          UIStates.empty(demo, { kind: 'no-results', title: 'No matching results', body: 'Clear the search to see all results.', actionLabel: 'Clear filters', action: function () { button.focus(); } });
          break;
        case 'loading':
          loading = UIStates.loading(demo, { label: 'Loading scan history', skeletonRows: 3, delayMs: 300, timeoutMs: 15000 });
          break;
        case 'error':
          UIStates.error(demo, { title: 'Scan history didn\'t load', body: 'Check your connection and try again.', retry: function () {
            var pending = UIStates.loading(demo, { label: 'Loading scan history', skeletonRows: 3 });
            loading = pending;
            setTimeout(function () {
              if (loading !== pending) return;
              pending.finish();
              UIStates.empty(demo, { title: 'No scans yet', body: 'Scan a QR code and it will appear here.' });
            }, 1200);
          }, ref: '7F3K-21QX', focus: true });
          break;
        case 'busy':
          UIStates.busy(button, function () { return new Promise(function (resolve) { setTimeout(resolve, 1200); }); }, { label: 'Saving…' });
          break;
      }
    });
  });
})();
