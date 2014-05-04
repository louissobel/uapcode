/*
  Pretty simple. Get page content, and send it to the extension
*/

chrome.runtime.sendMessage(null, {content: document.documentElement.outerHTML});