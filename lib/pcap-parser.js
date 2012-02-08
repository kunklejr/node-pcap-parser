var util = require('util');
var events = require('events');
var fs = require('fs');

var GLOBAL_HEADER_LENGTH = 24; //bytes
var PACKET_HEADER_LENGTH = 16; //bytes

var endianness = null; // gets set below

function onError(err) {
  this.emit('error', err);
}

function onEnd() {
  this.emit('end');
}

function onData(data) {
  if (this.errored) {
    return;
  }

  updateBuffer.call(this, data);
  while (this.state.call(this)) {}
}

function updateBuffer(data) {
  if (data === null || data === undefined) {
    return;
  }

  if (this.buffer === null) {
    this.buffer = data;
  } else {
    var extendedBuffer = new Buffer(this.buffer.length + data.length);
    this.buffer.copy(extendedBuffer);
    data.copy(extendedBuffer, this.buffer.length);
    this.buffer = extendedBuffer;
  }
}

function parseGlobalHeader() {
  var buffer = this.buffer;

  if (buffer.length >= GLOBAL_HEADER_LENGTH) {
    var magicNumber = buffer.toString('hex', 0, 4);

    // determine pcap endianness
    if (magicNumber == "a1b2c3d4") {
      endianness = "big";
    } else if (magicNumber == "d4c3b2a1") {
      endianness = "little";
    } else {
      this.errored = true;
      this.stream.pause();
      var msg = util.format('unknown magic number: %s', magicNumber);
      this.emit('error', new Error(msg));
      onEnd.call(this);
      return false;
    }

    if (endianness == "little") {
      var header = {
        magicNumber: buffer.readUInt32LE(0, true),
        majorVersion: buffer.readUInt16LE(4, true),
        minorVersion: buffer.readUInt16LE(6, true),
        gmtOffset: buffer.readInt32LE(8, true),
        timestampAccuracy: buffer.readUInt32LE(12, true),
        snapshotLength: buffer.readUInt32LE(16, true),
        linkLayerType: buffer.readUInt32LE(20, true)
      };
    } else {
      var header = {
        magicNumber: buffer.readUInt32BE(0, true),
        majorVersion: buffer.readUInt16BE(4, true),
        minorVersion: buffer.readUInt16BE(6, true),
        gmtOffset: buffer.readInt32BE(8, true),
        timestampAccuracy: buffer.readUInt32BE(12, true),
        snapshotLength: buffer.readUInt32BE(16, true),
        linkLayerType: buffer.readUInt32BE(20, true)
      };
    }

    if (header.majorVersion != 2 && header.minorVersion != 4) {
      this.errored = true;
      this.stream.pause();
      var msg = util.format('unsupported version %d.%d. pcap-parser only parses libpcap file format 2.4', header.majorVersion, header.minorVersion);
      this.emit('error', new Error(msg));
      onEnd.call(this);
    } else {
      this.emit('globalHeader', header);
      this.buffer = buffer.slice(GLOBAL_HEADER_LENGTH);
      this.state = parsePacketHeader;
      return true;
    }
  }

  return false;
}

function parsePacketHeader() {
  var buffer = this.buffer;

  if (buffer.length >= PACKET_HEADER_LENGTH) {
    if (endianness == "little") {
      var header = {
        timestampSeconds: buffer.readUInt32LE(0, true),
        timestampMicroseconds: buffer.readUInt32LE(4, true),
        capturedLength: buffer.readUInt32LE(8, true),
        originalLength: buffer.readUInt32LE(12, true)
      };
    } else {
      var header = {
        timestampSeconds: buffer.readUInt32BE(0, true),
        timestampMicroseconds: buffer.readUInt32BE(4, true),
        capturedLength: buffer.readUInt32BE(8, true),
        originalLength: buffer.readUInt32BE(12, true)
      };
    }

    this.currentPacketHeader = header;
    this.emit('packetHeader', header);
    this.buffer = buffer.slice(PACKET_HEADER_LENGTH);
    this.state = parsePacketBody;
    return true;
  }

  return false;
}

function parsePacketBody() {
  var buffer = this.buffer;

  if (buffer.length >= this.currentPacketHeader.capturedLength) {
    var data = buffer.slice(0, this.currentPacketHeader.capturedLength);

    this.emit('packetData', data);
    this.emit('packet', {
      header: this.currentPacketHeader,
      data: data
    });

    this.buffer = buffer.slice(this.currentPacketHeader.capturedLength);
    this.state = parsePacketHeader;
    return true;
  }

  return false;
}

function Parser(input) {
  if (typeof(input) == 'string') {
    this.stream = fs.createReadStream(input);
  } else {
    // assume a ReadableStream
    this.stream = input;
  }

  this.stream.pause();
  this.stream.on('data', onData.bind(this));
  this.stream.on('error', onError.bind(this));
  this.stream.on('end', onEnd.bind(this));

  this.buffer = null;
  this.state = parseGlobalHeader;
}
util.inherits(Parser, events.EventEmitter);

Parser.prototype.parse = function() {
  this.stream.resume();
};

exports.Parser = Parser;
