'use strict';
// Historical entry point retained only to explicitly reject the retired APK/TCP protocol.
// Do not register a connection, load old handlers, or mutate archived APK data.
function CreateConnection(socket) {
  socket.end('ERROR|APK_FEATURE_RETIRED\n');
  socket.destroySoon?.();
}
module.exports = { CreateConnection };
