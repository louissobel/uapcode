chrome.webRequest.onAuthRequired.addListener(function (details, callback) {
  console.log("AUTH", details);
  callback();
},
{
  urls: ["<all_urls>"]
},
["asyncBlocking", "requestBody"]
)

chrome.webRequest.onAttestationRequired.addListener(function (details, callback) {
  console.log("ATTEST", details);
  callback();
},
{
  urls: ["<all_urls>"]
},
["asyncBlocking", "requestBody"]
)