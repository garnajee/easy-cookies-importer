var statusElement = document.getElementById('status');

function setStatus(message, type) {
  if (!statusElement) return;
  statusElement.className = type ? 'status-' + type : '';
  statusElement.textContent = message;
}

function stripBom(text) {
  if (text && text.charCodeAt(0) === 0xFEFF) return text.slice(1);
  return text;
}

function detectFormat(text) {
  var t = stripBom(text).trim();
  if (!t) return null;
  if (t[0] === '[' || t[0] === '{') return 'json';
  return 'netscape';
}

function toBoolean(value) {
  if (typeof value === 'string') {
    return value.toLowerCase() === 'true' || value === '1';
  }
  return value === true || value === 1;
}

function parseExpiration(value) {
  if (value === undefined || value === null || value === '') return null;

  var expiration = Number(value);
  if (!isFinite(expiration)) {
    expiration = Date.parse(value);
    if (isNaN(expiration)) return null;
    expiration = expiration / 1000;
  } else if (expiration > 100000000000) {
    expiration = expiration / 1000;
  }

  return expiration > 0 ? Math.floor(expiration) : null;
}

function normalizeSameSite(value) {
  if (!value) return null;
  var sameSite = String(value).toLowerCase().replace(/-/g, '_');
  if (sameSite === 'none' || sameSite === 'no_restrictions') return 'no_restriction';
  if (sameSite === 'no_restriction' || sameSite === 'lax' || sameSite === 'strict' || sameSite === 'unspecified') {
    return sameSite;
  }
  return null;
}

function parseNetscape(text) {
  var lines = stripBom(text).split(/\r\n|\n|\r/);
  var cookies = [];

  for (var i = 0; i < lines.length; i++) {
    var line = lines[i];
    var trimmed = line.trim();
    if (!trimmed) continue;

    var httpOnly = false;
    if (trimmed.indexOf('#HttpOnly_') === 0) {
      var markerIndex = line.indexOf('#HttpOnly_');
      line = line.slice(0, markerIndex) + line.slice(markerIndex + 10);
      httpOnly = true;
    } else if (trimmed[0] === '#') {
      continue;
    }

    var parts = line.split('\t');
    if (parts.length < 7) continue;

    var domain = (parts[0] || '').trim().toLowerCase();
    var name = (parts[5] || '').trim();
    if (!domain || !name) continue;

    var cookie = {
      domain: domain,
      path: (parts[2] || '/').trim() || '/',
      secure: toBoolean((parts[3] || '').trim()),
      name: name,
      value: parts.slice(6).join('\t'),
      httpOnly: httpOnly
    };
    var expiration = parseExpiration((parts[4] || '').trim());
    if (expiration) cookie.expirationDate = expiration;
    cookies.push(cookie);
  }

  return cookies;
}

function parseJson(text) {
  var data;
  try {
    data = JSON.parse(stripBom(text));
  } catch (error) {
    throw new Error('Invalid JSON: ' + error.message);
  }

  if (data && !Array.isArray(data) && Array.isArray(data.cookies)) data = data.cookies;
  if (!Array.isArray(data)) data = [data];

  var cookies = [];
  for (var i = 0; i < data.length; i++) {
    var source = data[i];
    if (!source || typeof source !== 'object') continue;

    var domain = String(source.domain || source.Domain || source.host || source.Host || '').trim().toLowerCase();
    var name = String(source.name || source.Name || '').trim();
    if (!domain || !name) continue;

    var secureValue = source.secure;
    if (secureValue === undefined) secureValue = source.Secure;
    if (secureValue === undefined) secureValue = source.ssl;
    if (secureValue === undefined) secureValue = source.Ssl;

    var cookie = {
      domain: domain,
      path: String(source.path || source.Path || '/').trim() || '/',
      secure: toBoolean(secureValue),
      name: name,
      value: String(source.value !== undefined ? source.value : (source.Value !== undefined ? source.Value : '')),
      httpOnly: toBoolean(source.httpOnly !== undefined ? source.httpOnly : (source.HttpOnly !== undefined ? source.HttpOnly : source.httponly)),
      hostOnly: toBoolean(source.hostOnly !== undefined ? source.hostOnly : source.HostOnly)
    };

    var sameSite = normalizeSameSite(source.sameSite || source.SameSite);
    if (sameSite) cookie.sameSite = sameSite;

    var expiration = parseExpiration(
      source.expirationDate !== undefined ? source.expirationDate :
        (source.ExpirationDate !== undefined ? source.ExpirationDate :
          (source.expiry !== undefined ? source.expiry :
            (source.Expiry !== undefined ? source.Expiry :
              (source.expires !== undefined ? source.expires : source.Expires))))
    );
    if (expiration) cookie.expirationDate = expiration;

    if (source.storeId !== undefined || source.StoreId !== undefined) {
      cookie.storeId = String(source.storeId !== undefined ? source.storeId : source.StoreId);
    }
    cookies.push(cookie);
  }

  return cookies;
}

function parseCookies(text) {
  var format = detectFormat(text);
  if (!format) throw new Error('The file is empty or its format is not recognized.');

  var cookies = format === 'json' ? parseJson(text) : parseNetscape(text);
  if (!cookies.length) throw new Error('No valid cookies were found.');
  return cookies;
}

function setCookie(cookie) {
  return new Promise(function (resolve) {
    var host = cookie.domain.replace(/^\./, '');
    var path = cookie.path || '/';
    if (path[0] !== '/') path = '/' + path;

    var params = {
      url: (cookie.secure ? 'https://' : 'http://') + host + path,
      name: cookie.name,
      value: cookie.value,
      path: path,
      secure: !!cookie.secure
    };

    if (!cookie.hostOnly && cookie.name.indexOf('__Host-') !== 0) params.domain = cookie.domain;
    if (cookie.httpOnly) params.httpOnly = true;
    if (cookie.sameSite) params.sameSite = cookie.sameSite;
    if (cookie.expirationDate && cookie.expirationDate > Math.floor(Date.now() / 1000)) {
      params.expirationDate = cookie.expirationDate;
    }
    if (cookie.storeId) params.storeId = cookie.storeId;

    function result(cookieResult, runtimeError) {
      if (runtimeError || !cookieResult) {
        resolve({
          ok: false,
          name: cookie.name,
          domain: cookie.domain,
          reason: runtimeError ? runtimeError.message : 'The browser rejected the cookie.'
        });
      } else {
        resolve({ ok: true, name: cookie.name, domain: cookie.domain });
      }
    }

    if (typeof browser !== 'undefined' && browser.cookies) {
      browser.cookies.set(params).then(function (cookieResult) {
        result(cookieResult, null);
      }).catch(function (error) {
        result(null, error);
      });
    } else if (typeof chrome !== 'undefined' && chrome.cookies) {
      chrome.cookies.set(params, function (cookieResult) {
        result(cookieResult, chrome.runtime.lastError);
      });
    } else {
      result(null, new Error('The cookies API is unavailable.'));
    }
  });
}

function importCookies(cookies) {
  var results = { success: 0, failed: [] };
  return cookies.reduce(function (promise, cookie) {
    return promise.then(function () {
      return setCookie(cookie).then(function (result) {
        if (result.ok) results.success++;
        else results.failed.push(result);
      });
    });
  }, Promise.resolve()).then(function () {
    return results;
  });
}

function getSummary(cookies) {
  var seen = {};
  var domains = [];
  for (var i = 0; i < cookies.length; i++) {
    var domain = cookies[i].domain.replace(/^\./, '');
    if (!seen[domain]) {
      seen[domain] = true;
      domains.push(domain);
    }
  }
  return domains.join(', ');
}

function renderReport(report, cookies, sourceName) {
  if (!statusElement) return;

  statusElement.textContent = '';
  var failedCount = report.failed.length;
  statusElement.className = failedCount === 0 ? 'status-success' : (report.success > 0 ? 'status-warning' : 'status-error');

  var summary = document.createElement('div');
  if (failedCount === 0) {
    summary.textContent = 'Success: ' + report.success + ' cookie(s) imported from ' + sourceName + ' for ' + getSummary(cookies) + '.';
  } else if (report.success > 0) {
    summary.textContent = 'Partial import: ' + report.success + ' succeeded and ' + failedCount + ' failed from ' + sourceName + '.';
  } else {
    summary.textContent = 'Import failed: none of the ' + failedCount + ' cookie(s) from ' + sourceName + ' could be imported.';
  }
  statusElement.appendChild(summary);

  if (failedCount > 0) {
    var list = document.createElement('ul');
    var max = Math.min(failedCount, 5);
    for (var i = 0; i < max; i++) {
      var item = document.createElement('li');
      item.textContent = report.failed[i].name + ' @ ' + report.failed[i].domain + ': ' + report.failed[i].reason;
      list.appendChild(item);
    }
    if (failedCount > max) {
      var remaining = document.createElement('li');
      remaining.textContent = '… and ' + (failedCount - max) + ' more.';
      list.appendChild(remaining);
    }
    statusElement.appendChild(list);
  }
}

function processText(text, sourceName) {
  var cookies;
  try {
    cookies = parseCookies(text);
  } catch (error) {
    setStatus('Error: ' + error.message, 'error');
    return Promise.resolve();
  }

  setStatus('Importing ' + cookies.length + ' cookie(s)…', 'loading');
  return importCookies(cookies).then(function (report) {
    renderReport(report, cookies, sourceName);
  }).catch(function (error) {
    setStatus('Import error: ' + (error.message || String(error)), 'error');
  });
}

function processFile(file) {
  if (!file || !/\.(txt|json)$/i.test(file.name)) {
    setStatus('Error: only .txt and .json files are supported.', 'error');
    return;
  }

  setStatus('Reading ' + file.name + '…', 'loading');
  var reader = new FileReader();
  reader.onload = function (event) {
    processText(String(event.target.result || ''), file.name);
  };
  reader.onerror = function () {
    setStatus('Error: the file could not be read.', 'error');
  };
  reader.onabort = function () {
    setStatus('File selection cancelled.', 'warning');
  };
  try {
    reader.readAsText(file);
  } catch (error) {
    setStatus('Error: ' + (error.message || 'the file could not be read.'), 'error');
  }
}

var pasteButton = document.getElementById('paste-btn');
if (pasteButton) {
  pasteButton.addEventListener('click', function () {
    setStatus('', '');
    navigator.clipboard.readText().then(function (text) {
      if (!text.trim()) throw new Error('The clipboard is empty.');
      return processText(text, 'the clipboard');
    }).catch(function (error) {
      setStatus('Error: ' + (error.message || 'the clipboard could not be read.'), 'error');
    });
  });
}

var uploadButton = document.getElementById('upload-btn');
var fileInput = document.getElementById('file-input');
if (uploadButton && fileInput) {
  uploadButton.addEventListener('click', function () {
    fileInput.value = '';
    fileInput.click();
  });
  fileInput.addEventListener('change', function () {
    if (fileInput.files && fileInput.files[0]) processFile(fileInput.files[0]);
  });
}
