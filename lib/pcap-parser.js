var util = require('util');
var events = require('events');
var fs = require('fs');

var GLOBAL_HEADER_LENGTH = 24; //bytes
var PACKET_HEADER_LENGTH = 16; //bytes

function onData(data) {
  updateBuffer.call(this, data);

  switch (this.state) {
    case 'globalHeader':
      parseGlobalHeader.call(this);
      break;
    case 'packetHeader':
      parsePacketHeader.call(this);
      break;
    case 'packetBody':
      parsePacketBody.call(this);
      break;
  }
}

function onError(err) {
  this.emit('error', err);
}

function onEnd() {
  this.emit('end');
}

function updateBuffer(data) {
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
  if (this.buffer.length >= GLOBAL_HEADER_LENGTH) {
    this.emit('globalHeader', {
      magicNumber: this.buffer.readUInt32LE(0, true),
      majorVersion: this.buffer.readUInt16LE(4, true),
      minorVersion: this.buffer.readUInt16LE(6, true),
      gmtOffset: this.buffer.readInt32LE(8, true),
      timestampAccuracy: this.buffer.readUInt32LE(12, true),
      snapshotLength: this.buffer.readUInt32LE(16, true),
      linkLayerType: this.buffer.readUInt32LE(20, true)
    });

    this.buffer = this.buffer.slice(GLOBAL_HEADER_LENGTH);
    this.state = 'packetHeader';
  }
}

function parsePacketHeader() {
  if (this.buffer.length >= PACKET_HEADER_LENGTH) {
    var header = {
      timestampSeconds: this.buffer.readUInt32LE(0, true),
      timestampMicroseconds: this.buffer.readUInt32LE(4, true),
      includedLength: this.buffer.readUInt32LE(8, true),
      originalLength: this.buffer.readUInt32LE(12, true)
    };

    this.currentPacketHeader = header;
    this.emit('packetHeader', header);
    this.buffer = this.buffer.slice(PACKET_HEADER_LENGTH);
    this.state = 'packetBody';
  }
}

function parsePacketBody() {
  if (this.buffer.length >= this.currentPacketHeader.includedLength) {
    var data = this.buffer.slice(0, this.currentPacketHeader.includedLength);

    this.emit('packetData', data);
    this.emit('packet', {
      header: this.currentPacketHeader,
      data: data
    });

    this.buffer = this.buffer.slice(this.currentPacketHeader.includedLength);
    this.state = 'packetHeader';
  }
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
  this.state = 'globalHeader';
}
util.inherits(Parser, events.EventEmitter);

Parser.prototype.parse = function() {
  this.stream.resume();
};

exports.Parser = Parser;
