'use strict';

var Readable = require('readable-stream');
var util = require('util');
var events = require('events');
var fs = require('fs');

var GLOBAL_HEADER_LENGTH = 24; //bytes
var PACKET_HEADER_LENGTH = 16; //bytes

function onReadable() {
  if (this.error) {
    return;
  }
  while (this.state.call(this)) { }
}

function onEnd() {
  this.emit('end');
}

function parseGlobalHeader() {
  var buffer = this.source.read(GLOBAL_HEADER_LENGTH);
  if (!buffer) {
    return false;
  }

  var msg;
  var magicNumber = buffer.toString('hex', 0, 4);

  // determine pcap endianness
  if (magicNumber == "a1b2c3d4") {
    this.endianness = "BE";
  } else if (magicNumber == "d4c3b2a1") {
    this.endianness = "LE";
  } else {
    msg = util.format('unknown magic number: 0x%s', magicNumber.toString());
    this.error = new Error(msg);
    this.emit('error', this.error);
    this.emit('end');
    return false;
  }

  this.globalHeader = {
    magicNumber: buffer['readUInt32' + this.endianness](0, true),
    majorVersion: buffer['readUInt16' + this.endianness](4, true),
    minorVersion: buffer['readUInt16' + this.endianness](6, true),
    gmtOffset: buffer['readInt32' + this.endianness](8, true),
    timestampAccuracy: buffer['readUInt32' + this.endianness](12, true),
    snapshotLength: buffer['readUInt32' + this.endianness](16, true),
    linkLayerType: buffer['readUInt32' + this.endianness](20, true)
  };

  if (this.globalHeader.majorVersion != 2 && this.globalHeader.minorVersion != 4) {
    msg = util.format('unsupported version %d.%d. pcap-parser only parses libpcap file format 2.4', this.globalHeader.majorVersion, this.globalHeader.minorVersion);
    this.error = new Error(msg);
    this.emit('error', this.error);
    this.emit('end');
  } else {
    this.emit('globalHeader', this.globalHeader);
    this.buffer = buffer.slice(GLOBAL_HEADER_LENGTH);
    this.state = parsePacketHeader;
    return true;
  }
}

function parsePacketHeader() {
  var buffer = this.source.read(PACKET_HEADER_LENGTH);
  if (!buffer) {
    return false;
  }

  var header = {
    timestampSeconds: buffer['readUInt32' + this.endianness](0, true),
    timestampMicroseconds: buffer['readUInt32' + this.endianness](4, true),
    capturedLength: buffer['readUInt32' + this.endianness](8, true),
    originalLength: buffer['readUInt32' + this.endianness](12, true)
  };

  this.currentPacketHeader = header;
  this.emit('packetHeader', header);
  this.state = parsePacketBody;
  return true;
}

function parsePacketBody() {
  var buffer = this.source.read(this.currentPacketHeader.capturedLength);
  if (!buffer) {
    return false;
  }

  if (!this._readCallback) {
    this.error = new Error('No read method called expecting data');
    this.emit('error', this.error);
    this.emit('end');
    return false;
  }

  var packet = {
    header: this.currentPacketHeader,
    data: buffer
  };

  this.emit('packetData', buffer);
  this.emit('packet', packet);

  this.state = parsePacketHeader;
  this._readCallback(null, packet);
  return true;
}

function Parser(stream) {
  Readable.call(this, {
    objectMode: true
  });

  this.state = parseGlobalHeader;
  this.endianness = null;

  this.source = new Readable();
  this.source.wrap(stream);
  this.source.on('readable', onReadable.bind(this));
  this.source.on('end', onEnd.bind(this));
}
util.inherits(Parser, Readable);

Parser.prototype._read = function(size, callback) {
  if (this.error) {
    return callback(this.error);
  }
  this._readCallback = callback;
  return this.state.call(this);
};

exports.createParser = function(stream) {
  return new Parser(stream);
};
