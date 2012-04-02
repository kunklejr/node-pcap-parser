# pcap-parser

Packet capture (pcap) file parser for Node.js

## Installation

    $ npm install pcap-parser

## Usage

```javascript
var pcapp = require('pcap-parser');

var parser = pcapp.parse('/path/to/file.pcap');
parser.on('packet', function(packet) {
  // do your packet processing
});
```

## Events

pcap-parser emits five different events, only some of which you'll
likely care about. Each event is emitted from the parser created with
`pcapp.parse`. The `pcapp.parse` method can be passed a
file path or a readable stream.

pcap-parser only parses version 2.4 of the libpcap file format in big
or little endian format. Please see
http://wiki.wireshark.org/Development/LibpcapFileFormat for detailed
documentation of the pcap file format.

### globalHeader

Event fired after parsing the global pcap file header. The object passed
to your event listener would look something like

    {
      magicNumber: 2712847316,
      majorVersion: 2,
      minorVersion: 4,
      gmtOffset: 0,
      timestampAccuracy: 4,
      snapshotLength: 65535,
      linkLayerType: 1
    }

### packetHeader

Event fired after parsing each packet header. The object passed to your
event listener would look something like

    {
      timestampSeconds: 1254722767,
      timestampMicroseconds: 492060,
      capturedLength: 76,
      originalLength: 76
    }

### packetData

Event fired after parsing each packet's data. The argument passed to the
event listener is simply a buffer containing the packet data.

### packet

Event fired after parsing each packet. The data structure contains both
the header fields and packet data.

    {
      header: {
        timestampSeconds: 1254722767,
        timestampMicroseconds: 492060,
        capturedLength: 76,
        originalLength: 76
      },

      data: [Buffer]
    }

### end

Emitted after all packes in the file or stream have been parsed. There
are no arguments passed to the event listener.

### error

Emitted on any error from the underlying stream. The error object is
passed to the event listener.

## License

(The MIT License)

Copyright (c) 2012 Near Infinity Corporation

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
