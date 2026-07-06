var extensionApi = typeof browser !== 'undefined' ? browser : chrome;
var importerUrl = extensionApi.runtime.getURL('popup/main.html');

function findImporterWindow(windows) {
  for (var i = 0; i < windows.length; i++) {
    var tabs = windows[i].tabs || [];
    for (var j = 0; j < tabs.length; j++) {
      if (tabs[j].url === importerUrl) return windows[i];
    }
  }
  return null;
}

function openImporter() {
  extensionApi.windows.getAll({ populate: true, windowTypes: ['popup'] }).then(function (windows) {
    var existingWindow = findImporterWindow(windows);
    if (existingWindow) {
      return extensionApi.windows.update(existingWindow.id, { focused: true });
    }

    return extensionApi.windows.create({
      url: importerUrl,
      type: 'popup',
      width: 380,
      height: 230,
      focused: true
    });
  }).catch(function (error) {
    console.error('Could not open the cookie importer:', error);
  });
}

extensionApi.action.onClicked.addListener(openImporter);
