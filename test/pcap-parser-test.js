var vows = require('vows');
var assert = require('assert');
var fs = require('fs');
var path = require('path');
var pcapp = require('../lib/pcap-parser');

vows.describe('pcap-parser').addBatch({
  'given a bad/malformed pcap file': {
    topic: pcapp.parse(fs.createReadStream(path.join(__dirname, 'malformed.pcap'))),

    'the parser should emit an error event': {
      topic: function(parser) {
        parser.once('error', this.callback.bind(this, null));
      },

      'an error event should have been emitted': function(err) {
        assert.isNotNull(err);
      }
    }
  },

  'given a readable stream of a little-endian pcap file': {
    topic: pcapp.parse(fs.createReadStream(path.join(__dirname, 'smtp.pcap'))),

    'the parser should emit globalHeader events': {
      topic: function(parser) {
        parser.once('globalHeader', this.callback.bind(this, null));
      },

      'global header values should be correct': function(header) {
        assert.isNotNull(header);
        assert.equal(header.magicNumber, 2712847316);
        assert.equal(header.majorVersion, 2);
        assert.equal(header.minorVersion, 4);
        assert.equal(header.gmtOffset, 0);
        assert.equal(header.timestampAccuracy, 0);
        assert.equal(header.snapshotLength, 65535);
        assert.equal(header.linkLayerType, 1);
      }
    },

    'the parser should emit packetHeader events': {
      topic: function(parser) {
        parser.once('packetHeader', this.callback.bind(this, null));
      },

      'packet header values should be correct': function(packetHeader) {
        assert.isNotNull(packetHeader);
        assert.equal(packetHeader.timestampSeconds, 1254722767);
        assert.equal(packetHeader.timestampMicroseconds, 492060);
        assert.equal(packetHeader.capturedLength, 76);
        assert.equal(packetHeader.originalLength, 76);
      }
    },

    'the parser should emit packetData events': {
      topic: function(parser) {
        parser.once('packetData', this.callback.bind(this, null));
      },

      'packet data buffer should not be empty': function(packetData) {
        assert.isNotNull(packetData);
        assert.equal(packetData.length, 76);
      }
    },

    'the parser should emit packet events': {
      topic: function(parser) {
        parser.once('packet', this.callback.bind(this, null));
      },

      'packet values should be correct': function(packet) {
        assert.isNotNull(packet);
        assert.isDefined(packet.header);
        assert.isDefined(packet.data);
        assert.equal(packet.data.length, 76);
        assert.equal(packet.header.timestampSeconds, 1254722767);
        assert.equal(packet.header.timestampMicroseconds, 492060);
        assert.equal(packet.header.capturedLength, 76);
        assert.equal(packet.header.originalLength, 76);
      }
    },

    'the parser should emit an end event when finished': {
      topic: function(parser) {
        parser.on('end', this.callback.bind(this, null));
      },

      'it should occur': function() {}
    },

    'the parser should parse multiple packets': {
      topic: function(parser) {
        var count = 0;

        parser.on('packet', function(packet) {
          count++;
        }).on('end', function() {
          this.callback(null, count);
        }.bind(this));
      },

      'it should process 60 packets': function(count) {
        assert.equal(count, 60);
      }
    }
  },

  'given a readable stream of a big-endian pcap file': {
    topic: pcapp.parse(fs.createReadStream(path.join(__dirname, 'be.pcap'))),

    'the parser should emit globalHeader events': {
      topic: function(parser) {
        parser.once('globalHeader', this.callback.bind(this, null));
      },

      'global header values should be correct': function(header) {
        assert.isNotNull(header);
        assert.equal(header.magicNumber, 2712847316);
        assert.equal(header.majorVersion, 2);
        assert.equal(header.minorVersion, 4);
        assert.equal(header.gmtOffset, 0);
        assert.equal(header.timestampAccuracy, 0);
        assert.equal(header.snapshotLength, 9216);
        assert.equal(header.linkLayerType, 1);
      }
    },

    'the parser should emit packetHeader events': {
      topic: function(parser) {
        parser.once('packetHeader', this.callback.bind(this, null));
      },

      'packet header values should be correct': function(packetHeader) {
        assert.isNotNull(packetHeader);
        assert.equal(packetHeader.timestampSeconds, 3064);
        assert.equal(packetHeader.timestampMicroseconds, 714590);
        assert.equal(packetHeader.capturedLength, 42);
        assert.equal(packetHeader.originalLength, 60);
      }
    },

    'the parser should emit packetData events': {
      topic: function(parser) {
        parser.once('packetData', this.callback.bind(this, null));
      },

      'packet data buffer should not be empty': function(packetData) {
        assert.isNotNull(packetData);
        assert.equal(packetData.length, 42);
      }
    },

    'the parser should emit packet events': {
      topic: function(parser) {
        parser.once('packet', this.callback.bind(this, null));
      },

      'packet values should be correct': function(packet) {
        assert.isNotNull(packet);
        assert.isDefined(packet.header);
        assert.isDefined(packet.data);
        assert.equal(packet.data.length, 42);
        assert.equal(packet.header.timestampSeconds, 3064);
        assert.equal(packet.header.timestampMicroseconds, 714590);
        assert.equal(packet.header.capturedLength, 42);
        assert.equal(packet.header.originalLength, 60);
      }
    },

    'the parser should emit an end event when finished': {
      topic: function(parser) {
        parser.on('end', this.callback.bind(this, null));
      },

      'it should occur': function() {}
    },

    'the parser should parse multiple packets': {
      topic: function(parser) {
        var count = 0;

        parser.on('packet', function(packet) {
          count++;
        }).on('end', function() {
          this.callback(null, count);
        }.bind(this));
      },

      'it should process 5 packets': function(count) {
        assert.equal(count, 5);
      }
    }
  },

  'given a path to a pcap file': {
    topic: pcapp.parse(path.join(__dirname, 'smtp.pcap')),

    'the parser should emit all the same events': {
      topic: function(parser) {
        var events = {
          globalHeader: false,
          packetHeader: false,
          packetData: false,
          packet: false
        };

        function ifDone(eventType) {
          events[eventType] = true;
          if (events.globalHeader && events.packetHeader && events.packetData && events.packet) {
            this.callback(null, true);
          }
        }

        parser.once('globalHeader', ifDone.bind(this, 'globalHeader'));
        parser.once('packetHeader', ifDone.bind(this, 'packetHeader'));
        parser.once('packetData', ifDone.bind(this, 'packetData'));
        parser.once('packet', ifDone.bind(this, 'packet'));
      },

      'all events should have been emitted': function(confirmation) {
        assert.isTrue(confirmation);
      }
    }
  }
}).export(module);
