## 0.2.0

Breaking API:

  - Creating a parser is now done via the pcapp.parse method rather than
    new pcapp.Parser(). Explicitly calling the parse method on the
    returned parser is no longer necessary, or possible. All parsing
    events are emitted on the next tick.

## 0.2.1

Bug:

  - index.js was not updated to reflect the API change in 0.2.0