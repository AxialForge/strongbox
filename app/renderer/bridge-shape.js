// The one description of the `window.api` object the renderer uses.
//
// Leaves are channel names. A leaf starting with "!" is an event stream the UI subscribes to;
// everything else is a request. kit/renderer/webbridge.js turns it into fetch + EventSource.
// kit/test/contract.js checks that every request channel here is served by the core or the web
// shell, and that nothing is served without being listed here.
(function (root, shape) {
  if (typeof module !== 'undefined' && module.exports) module.exports = shape;
  else root.API_SHAPE = shape;
})(typeof self !== 'undefined' ? self : this, {
  // kit
  appInfo: 'app:info',
  settings: { get: 'settings:get', set: 'settings:set', replace: 'settings:replace' },
  update: { check: 'update:check', status: 'update:status', install: 'update:install' },
  sys: { stats: 'sys:stats' },
  db: { stats: 'db:stats' },
  logTail: 'log:tail',
  notifyTest: 'notify:test',
  prefs: { get: 'prefs:get', set: 'prefs:set' },
  security: { me: 'security:me', status: 'security:status', changePassword: 'security:changePassword', totpSetup: 'security:totpSetup', totpEnable: 'security:totpEnable', totpDisable: 'security:totpDisable', setOptions: 'security:setOptions', revoke: 'security:revoke', revokeOthers: 'security:revokeOthers', users: 'security:users', addUser: 'security:addUser', setRole: 'security:setRole', resetPassword: 'security:resetPassword', deleteUser: 'security:deleteUser', tlsEnable: 'security:tlsEnable' },
  status: { info: 'status:info', rotate: 'status:rotate' },
  dialog: { pickFolder: 'dialog:pickFolder', pickFile: 'dialog:pickFile' },
  shell: { open: 'shell:open', openExternal: 'shell:openExternal', showItem: 'shell:showItem' },
  // app
  data: { dashboard: 'data:dashboard', status: 'data:status' },
  vault: {
    status: 'vault:status', touch: 'vault:touch', create: 'vault:create', unlock: 'vault:unlock', lock: 'vault:lock', rewrap: 'vault:rewrap', newRecovery: 'vault:newRecovery',
    resetEmpty: 'vault:resetEmpty', rotate: 'vault:rotate', restoreCheck: 'vault:restoreCheck', backup: 'vault:backup', health: 'vault:health', audit: 'vault:audit',
    onLocked: '!vault:locked', onChanged: '!vault:changed',
  },
  tags: { list: 'tags:list', save: 'tags:save', delete: 'tags:delete' },
  templates: { list: 'templates:list', save: 'templates:save', delete: 'templates:delete' },
  network: { list: 'network:list' },
  breach: { status: 'breach:status', clear: 'breach:clear' },
  files: { delete: 'files:delete' },
  tabs: { list: 'tabs:list', save: 'tabs:save', reorder: 'tabs:reorder', delete: 'tabs:delete' },
  entries: {
    list: 'entries:list', print: 'entries:print', duplicate: 'entries:duplicate', bulk: 'entries:bulk', exportCsv: 'entries:exportCsv', search: 'entries:search', get: 'entries:get', save: 'entries:save', move: 'entries:move', reveal: 'entries:reveal', totp: 'entries:totp',
    delete: 'entries:delete', trash: 'entries:trash', restore: 'entries:restore', purge: 'entries:purge', importCsv: 'entries:importCsv',
  },
});
