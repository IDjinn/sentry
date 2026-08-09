//! MaxMindDB-based geo and ASN enrichment.
//!
//! Loads the GeoLite2-City and GeoLite2-ASN databases from disk and exposes a
//! cheap, allocation-light lookup. The daemon calls [`GeoLookup::enrich`]
//! during ingest to fill in `Event.geo` and `Event.asn` before the event
//! reaches the pipeline.

#![forbid(unsafe_code)]

use std::net::IpAddr;
use std::path::Path;

use sentry_core::event::GeoInfo;

/// MaxMindDB reader wrapper. Owns both the city and ASN databases.
pub struct GeoLookup {
    city: Option<maxminddb::Reader<Vec<u8>>>,
    asn: Option<maxminddb::Reader<Vec<u8>>>,
}

impl GeoLookup {
    /// Open the city and ASN databases from the given paths.
    ///
    /// Missing files are tolerated: the corresponding lookup will simply
    /// return `None`. This lets the daemon boot before the user has
    /// downloaded the databases (see `sentry init`).
    pub fn open(city_db: &Path, asn_db: &Path) -> Result<Self, GeoError> {
        let city = if city_db.exists() {
            Some(
                maxminddb::Reader::open_readfile(city_db)
                    .map_err(|e| GeoError::Open(e.to_string()))?,
            )
        } else {
            None
        };
        let asn = if asn_db.exists() {
            Some(
                maxminddb::Reader::open_readfile(asn_db)
                    .map_err(|e| GeoError::Open(e.to_string()))?,
            )
        } else {
            None
        };
        Ok(Self { city, asn })
    }

    /// Create an empty lookup (all lookups return `None`). Useful for tests.
    pub fn empty() -> Self {
        Self {
            city: None,
            asn: None,
        }
    }

    /// Look up the country / subdivision / city for an IP.
    pub fn lookup_geo(&self, ip: IpAddr) -> Option<GeoInfo> {
        let reader = self.city.as_ref()?;
        let city: maxminddb::geoip2::City = reader.lookup(ip).ok()?;
        let country = city
            .country
            .as_ref()
            .and_then(|c| c.iso_code)
            .map(String::from);
        let subdivision = city
            .subdivisions
            .as_ref()
            .and_then(|s| s.first())
            .and_then(|d| d.iso_code)
            .map(String::from);
        let city_name = city
            .city
            .as_ref()
            .and_then(|c| c.names.as_ref())
            .and_then(|n| n.get("en").copied())
            .map(String::from);
        let lat = city.location.as_ref().and_then(|l| l.latitude);
        let lon = city.location.as_ref().and_then(|l| l.longitude);
        Some(GeoInfo {
            country,
            subdivision,
            city: city_name,
            lat: lat.map(|f| f as f32),
            lon: lon.map(|f| f as f32),
        })
    }

    /// Look up the ASN for an IP.
    pub fn lookup_asn(&self, ip: IpAddr) -> Option<u32> {
        let reader = self.asn.as_ref()?;
        let asn: maxminddb::geoip2::Asn = reader.lookup(ip).ok()?;
        asn.autonomous_system_number
    }

    /// Enrich an event in place with geo and ASN data.
    pub fn enrich(&self, evt: &mut sentry_core::event::Event) {
        if evt.geo.is_none() {
            evt.geo = self.lookup_geo(evt.client_ip);
        }
        if evt.asn.is_none() {
            evt.asn = self.lookup_asn(evt.client_ip);
        }
    }
}

/// Geo-specific error type.
#[derive(Debug, thiserror::Error)]
pub enum GeoError {
    /// Could not open a database file.
    #[error("failed to open maxminddb: {0}")]
    Open(String),
}
