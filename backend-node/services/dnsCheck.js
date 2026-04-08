/**
 * dnsCheck.js
 * -----------
 * Real DNS reputation and resolution check.
 */

const dns = require("dns").promises;

/**
 * Check DNS records for a domain.
 * @param {string} hostname
 * @returns {Promise<{resolves: boolean, ips: string[], error: string|null}>}
 */
async function checkDNS(hostname) {
  try {
    const addresses = await dns.resolve4(hostname);
    return {
      resolves: addresses.length > 0,
      ips: addresses,
      error: null,
    };
  } catch (error) {
    if (error.code === "ENOTFOUND" || error.code === "ENODATA") {
      return { resolves: false, ips: [], error: "Domain does not resolve (could be a sinkholed or fake domain)" };
    }
    return { resolves: false, ips: [], error: error.message };
  }
}

module.exports = { checkDNS };
