# @isthisyou/dnssec-zone

Zone construction and DNSSEC for an "Is this you?" identity zone. The phone app depends on this package. It does not talk to Android.

## Display names

URI category names and known wallet types are display-only. They are not signed.

The master file lives in [james-stevens/IsThisYou.org](https://github.com/james-stevens/IsThisYou.org) and is served at `https://isthisyou.org/categories.json`. This package ships an offline copy at `data/categories.json` for when that URL cannot be fetched. Do not treat the copy in this repo as the file to publish.

`refreshCatalog` loads the bundled copy, then the last good cached copy if its `version` is higher. It fetches the URL at startup and at most once a day. A response is kept only when it parses and its `version` is greater than the copy already in use. Network errors, non-HTTPS URLs, and invalid JSON are ignored.

```json
{
  "version": 1,
  "uri_categories": [{ "id": 1, "name": "social" }],
  "wallet_types": [
    { "id": "paypal", "name": "PayPal", "identifier_hint": "13-character payer or merchant ID" }
  ]
}
```

`uri_categories[].id` is an integer of 1 or more. Priority 0 with weight 0 on a URI record is the single default URI, not a category. Unknown category numbers are shown as "other". Unknown wallet type ids are shown as the raw type string.

The placeholder table in the bundled file is social (1) and gaming (2), plus a few wallet types. The IsThisYou.org repo is where that list is finalised.
