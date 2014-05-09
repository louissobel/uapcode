

var tabContents = {}
  , requestsProcessed = {}
  ;


chrome.tabs.onUpdated.addListener(function (tabId, changes, tab) {
  if (tab.status === 'complete') {
    // Inject our script...
    chrome.tabs.executeScript(tabId, {file: 'get_content.js'}, function (r) {
      if (chrome.runtime.lastError) {
        // Ignore it
        console.log("Error injecting script into ", tab);
      } else {
        console.log("Injected Script into ", tab);
      }
    });
  }
});

chrome.runtime.onMessage.addListener(function (message, fromWhom) {
  tabContents[fromWhom.tab.id] = message.content;
  console.log("Got content for tab ", fromWhom.tab.id);
});

chrome.webRequest.onAttestationRequired.addListener(function (details, callback) {
  console.log("Attestation:", details);
  if (requestsProcessed.hasOwnProperty(details.requestId)) {
    // Then this is the second time we've seen the attestation.
    // Give up.
    return callback({
      cancel: true
    })
  } else {
    // Put it in. and continue
    requestsProcessed[details.requestId] = true;
    var content;
    if (tabContents.hasOwnProperty(details.tabId)) {
      // Then Let's use that.
      content = tabContents[details.tabId];
      console.log("Attestation request with content: ", content);
    } else {
      content = '';
      console.log("Attestation request with no content for tab");
    }
    var hash = CryptoJS.SHA1(content)
      , b64Hash = hash.toString(CryptoJS.enc.Base64)
      ;
    callback({
      authCredentials: {
        username: ''
      , password: b64Hash
      }
    });
  }
},
{
  urls: ["<all_urls>"]
},
["asyncBlocking"]
)