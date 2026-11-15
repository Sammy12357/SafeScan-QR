/* Accessible state primitives for server-rendered SafeScan pages. User-supplied
   strings enter the DOM only through textContent. No HTML or third-party code. */
(function (global) {
  'use strict';

  var ICONS = { scan: true, search: true, lock: true, warning: true, check: true, info: true };
  var busyTasks = new WeakMap();
  var activeLoads = new WeakMap();

  function element(tag, className, textValue) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (textValue !== undefined && textValue !== null) node.textContent = String(textValue);
    return node;
  }

  function icon(name, className) {
    var svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('class', className || 'state-icon');
    svg.setAttribute('aria-hidden', 'true');
    svg.setAttribute('focusable', 'false');
    var use = document.createElementNS('http://www.w3.org/2000/svg', 'use');
    use.setAttribute('href', '/static/icons/states.svg#' + (ICONS[name] ? name : 'info'));
    svg.appendChild(use);
    return svg;
  }

  function actionNode(label, href, callback, secondary) {
    if (!label) return null;
    var node = href ? element('a', secondary ? 'secondary-button' : 'primary-button', label) :
      element('button', secondary ? 'secondary-button' : 'primary-button', label);
    if (href) node.setAttribute('href', String(href));
    else node.type = 'button';
    if (typeof callback === 'function') node.addEventListener('click', callback);
    return node;
  }

  function appendActions(section, options) {
    var actions = element('div', 'state-actions');
    var primary = actionNode(options.actionLabel, options.actionHref, options.action, false);
    if (primary) actions.appendChild(primary);
    var secondary = options.secondary;
    if (secondary && secondary.label) {
      actions.appendChild(actionNode(secondary.label, secondary.href, secondary.action, true));
    }
    if (actions.childNodes.length) section.appendChild(actions);
  }

  function render(container, section) {
    if (!container) throw new TypeError('A state container is required');
    var pending = activeLoads.get(container);
    if (pending) pending.finish();
    container.replaceChildren(section);
    container.removeAttribute('aria-busy');
    return section;
  }

  function empty(container, options) {
    options = options || {};
    var kind = options.kind || 'first-use';
    var glyph = options.icon || (kind === 'no-results' ? 'search' : kind === 'no-access' ? 'lock' : 'scan');
    var section = element('section', 'state state-empty' + (options.compact ? ' state-compact' : ''));
    section.setAttribute('role', 'status');
    section.appendChild(icon(glyph));
    section.appendChild(element('h2', 'state-title', options.title || 'Nothing here yet'));
    if (options.body) section.appendChild(element('p', 'state-body', options.body));
    appendActions(section, options);
    return render(container, section);
  }

  function error(container, options) {
    options = options || {};
    var section = element('section', 'state state-error' + (options.compact ? ' state-compact' : ''));
    section.setAttribute('role', 'alert');
    section.appendChild(icon('warning'));
    section.appendChild(element('h2', 'state-title', options.title || 'We couldn\'t load this'));
    section.appendChild(element('p', 'state-body', options.body || 'Check your connection and try again.'));
    if (typeof options.retry === 'function') {
      appendActions(section, { actionLabel: options.retryLabel || 'Try again', action: options.retry });
    }
    if (options.ref) section.appendChild(element('p', 'state-ref', 'Reference: ' + options.ref));
    render(container, section);
    if (options.focus) {
      section.tabIndex = -1;
      section.focus();
    }
    return section;
  }

  function notice(container, options) {
    options = options || {};
    var types = { info: 'info', success: 'success', warning: 'warning', danger: 'danger' };
    var type = types[options.type] || 'info';
    var banner = element('div', 'notice notice-' + type);
    banner.setAttribute('role', type === 'danger' ? 'alert' : 'status');
    banner.appendChild(icon(type === 'success' ? 'check' : type === 'danger' || type === 'warning' ? 'warning' : 'info', 'notice-icon'));
    banner.appendChild(element('p', 'notice-body', options.message || ''));
    return render(container, banner);
  }

  function skeleton(rows) {
    var wrapper = element('div', 'skeleton');
    wrapper.setAttribute('aria-hidden', 'true');
    var count = Math.max(1, Math.min(8, Number(rows) || 3));
    for (var i = 0; i < count; i += 1) {
      var row = element('div', 'skeleton-row');
      row.appendChild(element('span', 'skeleton-line'));
      row.appendChild(element('span', 'skeleton-line'));
      wrapper.appendChild(row);
    }
    return wrapper;
  }

  function loading(container, options) {
    if (!container) throw new TypeError('A state container is required');
    var previous = activeLoads.get(container);
    if (previous) previous.finish();
    options = options || {};
    var done = false;
    var shown = null;
    var announcer = null;
    var announceTimer = null;
    var delay = Math.max(0, Number(options.delayMs === undefined ? 300 : options.delayMs));
    var timeout = Math.max(1, Number(options.timeoutMs === undefined ? 15000 : options.timeoutMs));
    container.setAttribute('aria-busy', 'true');

    var delayTimer = global.setTimeout(function () {
      if (done) return;
      var section = element('section', 'state state-loading' + (options.compact ? ' state-compact' : ''));
      section.appendChild(element('span', 'state-spinner'));
      section.appendChild(element('p', 'state-body', options.label || 'Loading'));
      if (options.skeletonRows) section.appendChild(skeleton(options.skeletonRows));
      container.replaceChildren(section);
      shown = section;
      announcer = element('span', 'state-sr-only');
      announcer.setAttribute('role', 'status');
      if (container.parentNode) container.parentNode.insertBefore(announcer, container.nextSibling);
      else section.appendChild(announcer);
      announceTimer = global.setTimeout(function () {
        if (!done) announcer.textContent = options.label || 'Loading';
      }, 0);
    }, delay);

    var timeoutTimer = global.setTimeout(function () {
      if (done) return;
      finish();
      error(container, {
        title: options.timeoutTitle || 'This is taking longer than expected',
        body: options.timeoutBody || 'Check your connection and try again.',
        retry: typeof options.retry === 'function' ? options.retry : function () { global.location.reload(); },
        focus: true
      });
      if (typeof options.onTimeout === 'function') options.onTimeout();
    }, timeout);

    function finish() {
      if (done) return;
      done = true;
      global.clearTimeout(delayTimer);
      global.clearTimeout(timeoutTimer);
      global.clearTimeout(announceTimer);
      container.removeAttribute('aria-busy');
      if (shown && shown.parentNode === container) shown.remove();
      if (announcer) announcer.remove();
      if (activeLoads.get(container) === controller) activeLoads.delete(container);
    }

    var controller = { finish: finish, cancel: finish, get shown() { return Boolean(shown); } };
    activeLoads.set(container, controller);
    return controller;
  }

  function busy(button, task, options) {
    if (!button) throw new TypeError('A button is required');
    if (busyTasks.has(button)) return busyTasks.get(button);
    options = options || {};
    var oldNodes = Array.from(button.childNodes);
    var wasDisabled = button.disabled;
    var oldBusy = button.getAttribute('aria-busy');
    var spinner = element('span', 'button-spinner');
    spinner.setAttribute('aria-hidden', 'true');
    button.replaceChildren(spinner, document.createTextNode(options.label || 'Working…'));
    button.setAttribute('aria-busy', 'true');
    button.disabled = true;
    var stillTimer = global.setTimeout(function () {
      button.lastChild.textContent = options.stillWorkingLabel || 'Still working…';
    }, options.stillWorkingMs || 10000);
    var pending = Promise.resolve().then(function () {
      return typeof task === 'function' ? task() : task;
    }).finally(function () {
      global.clearTimeout(stillTimer);
      button.replaceChildren.apply(button, oldNodes);
      button.disabled = wasDisabled;
      if (oldBusy === null) button.removeAttribute('aria-busy');
      else button.setAttribute('aria-busy', oldBusy);
      busyTasks.delete(button);
    });
    busyTasks.set(button, pending);
    return pending;
  }

  function fetchJson(url, options) {
    options = options || {};
    var headers = new Headers(options.headers || {});
    headers.set('Accept', 'application/json');
    headers.set('X-Requested-With', 'fetch');
    var requestOptions = Object.assign({}, options, { headers: headers });
    return global.fetch(url, requestOptions).then(function (response) {
      return response.json().catch(function () { return {}; }).then(function (payload) {
        if (response.ok) return payload;
        var problem = new Error(typeof payload.error === 'string' ? payload.error : 'We couldn\'t complete that request.');
        problem.code = payload.code || 'request_failed';
        problem.hint = payload.hint || '';
        problem.status = response.status;
        problem.requestId = payload.request_id || response.headers.get('X-Request-ID') || '';
        problem.retryAfter = response.headers.get('Retry-After') || '';
        throw problem;
      });
    }).catch(function (problem) {
      if (problem && problem.code) throw problem;
      var offline = global.navigator && global.navigator.onLine === false;
      var friendly = new Error(offline ? 'You\'re offline. Reconnect and try again.' : 'We couldn\'t connect. Check your connection and try again.');
      friendly.code = offline ? 'offline' : 'network_error';
      throw friendly;
    });
  }

  global.UIStates = Object.freeze({ empty: empty, error: error, notice: notice, loading: loading, busy: busy, fetchJson: fetchJson });
})(window);
