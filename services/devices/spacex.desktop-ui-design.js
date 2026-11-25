'use strict';

const store = require('../bootstrap/spacex.desktop-bootstrap-store');
const audit = require('../storage/spacex.desktop-operation-audit');
const protocol = require('../protocol/spacex.packet-schema');

const BASE = Object.freeze({x:0,y:0,scale:100,stars:100,labelX:0,labelY:0,labelScale:100});
const EMPTY = Object.freeze({version:1,revision:0,b:BASE,o:BASE});
const MAX_REVISION = 2147483647;

function Read(db = store.Load()) {
  return structuredClone(db.desktopDesign ?? EMPTY);
}

function Validate(profile) {
  return protocol.ValidateDocument('desktopDesign', profile);
}

function Fail(code, status) {
  const error = Error(code);
  error.desktopError = true;
  error.status = status;
  throw error;
}

function Publish(body, actor) {
  try {
    Validate(body);
  } catch (error) {
    if (error.message !== 'PROTOCOL_SCHEMA_INVALID') throw error;
    Fail('DESKTOP_DESIGN_INVALID', 400);
  }
  const {revision, b, o} = body;
  if (revision === MAX_REVISION) Fail('DESKTOP_DESIGN_REVISION_EXHAUSTED', 409);
  if (revision !== Read().revision) Fail('DESKTOP_DESIGN_CONFLICT', 409);
  return audit.Run('ADMIN_DESKTOP_DESIGN_PUBLISH', actor, {component:'BO'}, db => {
    if (revision !== Read(db).revision) Fail('DESKTOP_DESIGN_CONFLICT', 409);
    db.desktopDesign = {version:1, revision:revision + 1, b:structuredClone(b), o:structuredClone(o)};
    return Read(db);
  });
}

module.exports = {Read, Validate, Publish};
