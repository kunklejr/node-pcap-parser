'use strict';

//var vows = require('vows');
//var assert = require('assert');
var fs = require('fs');
var path = require('path');
var pcapp = require('../lib/pcap-parser');

module.exports = {
  'bad/malformed pcap file': function(test) {
    var parser = pcapp.createParser(fs.createReadStream(path.join(__dirname, 'malformed.pcap')));
    var errOccured;
    parser.on('error', function(err) {
      if (errOccured) {
        return test.done(new Error('Error called multiple times'));
      }
      errOccured = err;
      test.ok(err);
    });
    parser.on('end', function() {
      test.ok(errOccured);
      test.done();
    });
    parser.resume();
  },

  'little-endian pcap file': function(test) {
    var parser = pcapp.createParser(fs.createReadStream(path.join(__dirname, 'smtp.pcap')));
    var foundGlobalHeader;
    var packetHeaders = [];
    var packetDatas = [];
    var packets = [];
    parser.on('globalHeader', function(globalHeader) {
      foundGlobalHeader = globalHeader;
    });
    parser.on('packetHeader', function(packetHeader) {
      packetHeaders.push(packetHeader);
    });
    parser.on('packetData', function(packetData) {
      packetDatas.push(packetData);
    });
    parser.on('packet', function(packet) {
      packets.push(packet);
    });
    parser.on('end', function() {
      test.ok(foundGlobalHeader);
      test.equals(foundGlobalHeader.magicNumber, 2712847316);
      test.equals(foundGlobalHeader.majorVersion, 2);
      test.equals(foundGlobalHeader.minorVersion, 4);
      test.equals(foundGlobalHeader.gmtOffset, 0);
      test.equals(foundGlobalHeader.timestampAccuracy, 0);
      test.equals(foundGlobalHeader.snapshotLength, 65535);
      test.equals(foundGlobalHeader.linkLayerType, 1);

      test.equals(packetHeaders.length, 60);
      test.equals(packetHeaders[0].timestampSeconds, 1254722767);
      test.equals(packetHeaders[0].timestampMicroseconds, 492060);
      test.equals(packetHeaders[0].capturedLength, 76);
      test.equals(packetHeaders[0].originalLength, 76);

      test.equals(packetDatas.length, 60);
      test.equals(packetDatas[0].length, 76);

      test.equals(packets.length, 60);
      test.ok(packets[0].header);
      test.ok(packets[0].data);
      test.equals(packets[0].data.length, 76);
      test.equals(packets[0].header.timestampSeconds, 1254722767);
      test.equals(packets[0].header.timestampMicroseconds, 492060);
      test.equals(packets[0].header.capturedLength, 76);
      test.equals(packets[0].header.originalLength, 76);

      test.done();
    });
    parser.resume();
  },

  'big-endian pcap file': function(test) {
    var parser = pcapp.createParser(fs.createReadStream(path.join(__dirname, 'be.pcap')));
    var foundGlobalHeader;
    var packetHeaders = [];
    var packetDatas = [];
    var packets = [];
    parser.on('globalHeader', function(globalHeader) {
      foundGlobalHeader = globalHeader;
    });
    parser.on('packetHeader', function(packetHeader) {
      packetHeaders.push(packetHeader);
    });
    parser.on('packetData', function(packetData) {
      packetDatas.push(packetData);
    });
    parser.on('packet', function(packet) {
      packets.push(packet);
    });
    parser.on('end', function() {
      test.ok(foundGlobalHeader);
      test.equals(foundGlobalHeader.magicNumber, 2712847316);
      test.equals(foundGlobalHeader.majorVersion, 2);
      test.equals(foundGlobalHeader.minorVersion, 4);
      test.equals(foundGlobalHeader.gmtOffset, 0);
      test.equals(foundGlobalHeader.timestampAccuracy, 0);
      test.equals(foundGlobalHeader.snapshotLength, 9216);
      test.equals(foundGlobalHeader.linkLayerType, 1);

      test.equals(packetHeaders.length, 5);
      test.equals(packetHeaders[0].timestampSeconds, 3064);
      test.equals(packetHeaders[0].timestampMicroseconds, 714590);
      test.equals(packetHeaders[0].capturedLength, 42);
      test.equals(packetHeaders[0].originalLength, 60);

      test.equals(packetDatas.length, 5);
      test.equals(packetDatas[0].length, 42);

      test.equals(packets.length, 5);
      test.ok(packets[0].header);
      test.ok(packets[0].data);
      test.equals(packets[0].data.length, 42);
      test.equals(packets[0].header.timestampSeconds, 3064);
      test.equals(packets[0].header.timestampMicroseconds, 714590);
      test.equals(packets[0].header.capturedLength, 42);
      test.equals(packets[0].header.originalLength, 60);

      test.done();
    });
    parser.resume();
  },

  'little-endian pcap file using readable interface': function(test) {
    var parser = pcapp.createParser(fs.createReadStream(path.join(__dirname, 'smtp.pcap')));
    var packets = [];

    parser.on('readable', function() {
      if (parser.globalHeader) {
        test.equals(parser.globalHeader.magicNumber, 2712847316);
        test.equals(parser.globalHeader.majorVersion, 2);
        test.equals(parser.globalHeader.minorVersion, 4);
        test.equals(parser.globalHeader.gmtOffset, 0);
        test.equals(parser.globalHeader.timestampAccuracy, 0);
        test.equals(parser.globalHeader.snapshotLength, 65535);
        test.equals(parser.globalHeader.linkLayerType, 1);
      }

      var packet;
      while (packet = parser.read(1)) {
        packets.push(packet);
      }
    });
    parser.on('end', function() {
      test.equals(packets.length, 60);
      test.ok(packets[0].header);
      test.ok(packets[0].data);
      test.equals(packets[0].data.length, 76);
      test.equals(packets[0].header.timestampSeconds, 1254722767);
      test.equals(packets[0].header.timestampMicroseconds, 492060);
      test.equals(packets[0].header.capturedLength, 76);
      test.equals(packets[0].header.originalLength, 76);
      test.done();
    });
    parser.resume();
  }
};

