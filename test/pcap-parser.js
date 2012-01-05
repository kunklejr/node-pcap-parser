var vows = require('vows');
var assert = require('assert');
var fs = require('fs');
var path = require('path');
var pcapp = require('../index.js');

vows.describe('pcap-parser').addBatch({
  'given a readable stream of a pcap file': {
    topic: new pcapp.Parser(fs.createReadStream(path.join(__dirname, 'smtp.pcap'))),

    'the parser should emit globalHeader events': {
      topic: function(parser) {
        parser.once('globalHeader', this.callback.bind(this, null));
        parser.parse();
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
        parser.parse();
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
        parser.parse();
      },

      'packet data buffer should not be empty': function(packetData) {
        assert.isNotNull(packetData);
        assert.equal(packetData.length, 76);
      }
    },

    'the parser should emit packet events': {
      topic: function(parser) {
        parser.once('packet', this.callback.bind(this, null));
        parser.parse();
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

        parser.parse();
      },

      'it should process 60 packets': function(count) {
        assert.equal(count, 60);
      }
    }
  },

  'given a path to a pcap file': {
    topic: new pcapp.Parser(path.join(__dirname, 'smtp.pcap')),

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
        parser.parse();
      },

      'all events should have been emitted': function(confirmation) {
        assert.isTrue(confirmation);
      },
    }
  }
}).export(module);
