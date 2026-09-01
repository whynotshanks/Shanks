// GeoIP Service — geolocates public IP addresses using ipwho.is API
import type { GeoLocation, IPIndicator } from "./types";

const GEOAPI_URL = "https://ipwho.is";

export async function geolocateIP(ip: string): Promise<GeoLocation> {
  try {
    const response = await fetch(`${GEOAPI_URL}/${ip}`, {
      signal: AbortSignal.timeout(8000),
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();

    if (!data.success) {
      return {
        ip,
        country: "Unknown",
        countryCode: "",
        region: "",
        city: "",
        latitude: 0,
        longitude: 0,
        isp: "",
        asn: "",
        org: "",
        source: GEOAPI_URL,
        success: false,
      };
    }

    return {
      ip,
      country: data.country || "Unknown",
      countryCode: data.country_code || "",
      region: data.region || "",
      city: data.city || "",
      latitude: data.latitude || 0,
      longitude: data.longitude || 0,
      isp: data.connection?.isp || "",
      asn: data.connection?.asn ? `AS${data.connection.asn}` : (data.connection?.asn || ""),
      org: data.connection?.org || "",
      source: GEOAPI_URL,
      success: true,
    };
  } catch {
    return {
      ip,
      country: "Unknown",
      countryCode: "",
      region: "",
      city: "",
      latitude: 0,
      longitude: 0,
      isp: "",
      asn: "",
      org: "",
      source: GEOAPI_URL,
      success: false,
    };
  }
}

export async function geolocateIPs(ips: IPIndicator[]): Promise<GeoLocation[]> {
  const publicIPs = ips.filter((ip) => ip.classification === "public");
  if (publicIPs.length === 0) return [];

  const results = await Promise.all(
    publicIPs.map(async (ip) => {
      const geo = await geolocateIP(ip.address);
      return geo;
    })
  );

  return results;
}
