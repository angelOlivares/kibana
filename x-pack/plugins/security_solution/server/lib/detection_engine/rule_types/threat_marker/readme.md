# Threat Marker rule

This rule enriches input events with `threat.detection.indicator` and `threat.detection.timestamp` fields,
if they match any indicator stored inside IOC indices.

## How to get matching results?

Threat Intelligence will most likely use some kind of aggregation to group the results for display, eg:

```
GET filebeat-*/_search
{
  "size": 0,
  "aggs": {
    "urls": {
      "terms": {
        "field": "threat.detection.indicator",
        "size": 50
      }
    }
  }
}
```