//! The page the authorization server answers a sign-in, consent or logout form
//! with when that form's chain can end at a client: a 200 that moves on by
//! `<meta http-equiv="refresh">`, not a 303, so that a strict `form-action`
//! never has to name the client's redirect. A script playing the browser over
//! HTTP follows it as a browser does, and this reads where to: the inverse of
//! the server's page, undoing exactly what its escaping does, `&amp;` last.

/**
 * The page's target, or undefined for any response that is not that page.
 * @param {number | undefined} status
 * @param {string} html
 * @returns {string | undefined}
 */
export function leavingPageTarget(status, html) {
  if (status !== 200) return undefined;
  const m = /<meta http-equiv="refresh" content="0;url=([^"]*)"/.exec(html);
  if (!m) return undefined;
  return m[1]
    .replace(/&#x27;/g, "'")
    .replace(/&quot;/g, '"')
    .replace(/&gt;/g, ">")
    .replace(/&lt;/g, "<")
    .replace(/&amp;/g, "&");
}
