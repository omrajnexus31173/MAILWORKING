/* MailTrace AI — geolocation presentation helpers.
   Everything here is about HONESTY: the UI must never claim a precision the data does not have,
   and must never plot a pin where no coordinates were returned. */
(function () {
  "use strict";

  var LEVEL_ORDER = { unknown: 0, country: 1, region: 2, city: 3, private: 1 };

  /* Normalise any geo record (backend geo_precision block, legacy record, or trace hop) */
  function precision(rec) {
    rec = rec || {};
    var p = rec.geo_precision || {};
    var lat = num(rec.lat), lon = num(rec.lon);
    var coords = p.has_coordinates != null
      ? !!p.has_coordinates
      : (lat != null && lon != null && Math.abs(lat) <= 90 && Math.abs(lon) <= 180);
    var level = p.level || guessLevel(rec, coords);
    var city = (rec.city || "").trim(), region = (rec.regionName || rec.region || "").trim(), country = (rec.country || "").trim();
    if (!country || country === "Unknown") level = coords ? (city ? "city" : region ? "region" : "country") : "unknown";
    return {
      level: level, coords: coords, lat: lat, lon: lon,
      city: city, region: region, country: (country && country !== "Unknown") ? country : "",
      confidence: p.confidence != null ? p.confidence : null,
      label: p.label || labelFor(level),
      radius_km: p.radius_km != null ? p.radius_km : null,
      caveat: p.caveat || "", approximate: p.approximate != null ? p.approximate : (level !== "city")
    };
  }
  function num(v) { var f = parseFloat(v); return (isFinite(f) ? f : null); }
  function guessLevel(rec, coords) {
    if (rec.status === "private") return "private";
    if (!coords) return (rec.country && rec.country !== "Unknown") ? "country" : "unknown";
    if (rec.city) return "city";
    if (rec.regionName || rec.region) return "region";
    return rec.country ? "country" : "unknown";
  }
  function labelFor(level) {
    return { city: "City-level", region: "Region-level (approximate)", country: "Country-level (approximate)",
             private: "Private / internal network", unknown: "Location unavailable" }[level] || "Unknown";
  }

  /* Human place string that only contains what is actually known */
  function place(prec) {
    var parts = [];
    if (prec.level === "city" && prec.city) parts.push(prec.city);
    if ((prec.level === "city" || prec.level === "region") && prec.region) parts.push(prec.region);
    if (prec.country) parts.push(prec.country);
    if (!parts.length) return prec.level === "private" ? "Private / internal network" : "Location unavailable";
    return parts.join(", ");
  }

  /* Coordinates string — suppressed (not guessed) when unavailable */
  function coordsText(prec) {
    if (!prec.coords || prec.lat == null || prec.lon == null) return null;
    return Math.abs(prec.lat).toFixed(2) + "°, " + Math.abs(prec.lon).toFixed(2) + "° " +
      (prec.lat >= 0 ? "N" : "S") + " / " + (prec.lon >= 0 ? "E" : "W");
  }

  function badgeClass(level) {
    return { city: "ok", region: "warn", country: "warn", private: "mut", unknown: "mut" }[level] || "mut";
  }

  /* Badge markup for the precision envelope */
  function badge(rec) {
    var p = precision(rec);
    var extra = p.radius_km ? " ±" + p.radius_km + " km" : "";
    return '<span class="geo-badge ' + badgeClass(p.level) + '" title="' + esc(p.caveat || p.label) + '">' +
      '<i class="geo-dot"></i>' + esc(p.label) + extra + '</span>';
  }

  /* Coordinates row: shows the real numbers, or an explicit unavailable state */
  function coordsRow(rec) {
    var p = precision(rec), t = coordsText(p);
    if (!t) {
      return '<span class="geo-na">' + (p.country
        ? "No coordinates returned — country-level only (" + esc(p.country) + ")"
        : "Coordinates unavailable") + '</span>';
    }
    return '<span class="mono geo-coords">' + esc(t) + '</span>' +
      (p.approximate ? ' <span class="geo-approx">approx.</span>' : "");
  }

  function esc(s) { return String(s == null ? "" : s).replace(/[&<>"]/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]; }); }

  window.MTgeo = {
    precision: precision, place: place, coordsText: coordsText, badge: badge,
    coordsRow: coordsRow, labelFor: labelFor, LEVEL_ORDER: LEVEL_ORDER, esc: esc
  };
})();
