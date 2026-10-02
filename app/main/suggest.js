'use strict';
// Suggestions for the review queue: a type and tags from what a login is for. Plain rules, no network: the site is never contacted.
const RULES = [
  ['banking', ['chase', 'bankofamerica', 'wellsfargo', 'capitalone', 'citi', 'discover', 'americanexpress', 'amex', 'usbank', 'pnc', 'schwab', 'fidelity', 'vanguard', 'paypal', 'venmo', 'zelle', 'coinbase', 'robinhood', 'sofi', 'ally.com', 'navyfederal', 'creditkarma', 'turbotax', 'irs.gov', 'bank', 'credit', 'loan', 'mortgage']],
  ['shopping', ['amazon', 'ebay', 'walmart', 'target.com', 'etsy', 'bestbuy', 'newegg', 'aliexpress', 'costco', 'homedepot', 'lowes', 'wayfair', 'shein', 'temu', 'shop', 'store']],
  ['social', ['facebook', 'instagram', 'twitter', 'x.com', 'linkedin', 'reddit', 'pinterest', 'tiktok', 'snapchat', 'tumblr', 'discord', 'whatsapp', 'telegram', 'mastodon', 'threads.net']],
  ['streaming', ['netflix', 'hulu', 'disneyplus', 'spotify', 'youtube', 'twitch', 'plex', 'hbomax', 'max.com', 'primevideo', 'paramountplus', 'peacocktv', 'crunchyroll', 'pandora', 'audible']],
  ['dev', ['github', 'gitlab', 'bitbucket', 'stackoverflow', 'npmjs', 'docker', 'cloudflare', 'digitalocean', 'heroku', 'vercel', 'netlify', 'aws.amazon', 'console.aws', 'azure', 'jetbrains', 'atlassian', 'pypi']],
  ['gaming', ['steampowered', 'steamcommunity', 'epicgames', 'xbox', 'playstation', 'nintendo', 'blizzard', 'battle.net', 'ea.com', 'ubisoft', 'gog.com', 'roblox', 'minecraft']],
  ['email', ['gmail', 'mail.google', 'webmail', 'outlook', 'live.com', 'yahoo', 'proton', 'icloud', 'aol.com', 'fastmail', 'zoho']],
  ['utilities', ['comcast', 'xfinity', 'verizon', 'att.com', 'tmobile', 'spectrum', 'duke-energy', 'coned', 'nationalgrid', 'centurylink', 'cox.com', 'sprint', 'republicservices', 'water', 'electric', 'energy']],
  ['travel', ['delta', 'united.com', 'southwest', 'jetblue', 'booking.com', 'expedia', 'airbnb', 'uber', 'lyft', 'marriott', 'hilton', 'tripadvisor', 'kayak', 'airlines']],
  ['health', ['mychart', 'cigna', 'aetna', 'unitedhealth', 'uhc', 'anthem', 'kaiser', 'cvs', 'walgreens', 'goodrx', 'labcorp', 'questdiagnostics', 'health']],
  ['software', ['adobe', 'autodesk', 'microsoft', 'apple.com', 'dropbox', 'box.com', 'evernote', 'notion', 'slack', 'zoom', '1password', 'lastpass', 'bitwarden']],
  ['education', ['.edu', 'coursera', 'udemy', 'khanacademy', 'duolingo', 'blackboard']],
  ['government', ['.gov']],
];
/** The host of a login address; an Android app entry (android://hash@com.example.app/) gives its package name. */
function hostOf(u) {
  return String(u || '').trim().toLowerCase().replace(/^[a-z][a-z0-9+.-]*:\/\//, '').replace(/^[^@/]*@/, '').replace(/^www\./, '').replace(/[/?#].*$/, '').replace(/:\d+$/, '');
}
const isLocal = (h) => /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.)/.test(h) || h === 'localhost' || /^\d{1,3}(\.\d{1,3}){3}$/.test(h) || /\.(local|home|lan|internal|localdomain)$/.test(h) || !h.includes('.');
/** → { host, builtin: 'hardware' | 'websites' | 'email', tags: [..], reason } */
function suggest(item, learned = null) {
  const url = String(item.url || ''), host = hostOf(url);
  if (host && learned && learned[host]) return { host, builtin: null, learned: learned[host], tags: learned[host].tags || [], reason: 'like the last one from this site' };
  if (/^android:\/\//i.test(url)) return { host, builtin: 'websites', tags: ['android-app'], reason: 'an Android app' };
  if (host && isLocal(host)) return { host, builtin: 'hardware', tags: ['network'], reason: 'a local address (a router, NAS or device)' };
  for (const [tag, words] of RULES) if (host && words.some(w => host.includes(w))) return { host, builtin: tag === 'email' ? 'email' : 'websites', tags: [tag], reason: `looks like ${tag}` };
  return { host, builtin: 'websites', tags: [], reason: '' };
}
module.exports = { RULES, hostOf, isLocal, suggest };
