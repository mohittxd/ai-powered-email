import { useEffect, useRef } from 'react'
import { MapPin } from 'lucide-react'

// We load Leaflet dynamically to avoid SSR issues
let L = null

const THREAT_COLORS = {
  tor_exit_node: '#ff4757',
  vpn_provider: '#ff6b35',
  known_hosting_provider: '#ffa502',
  default: '#4fc3f7',
}

function getMarkerColor(hop) {
  if (!hop.ip || hop.is_private) return '#4a6280'
  const flags = hop.threat_flags || []
  if (flags.includes('tor_exit_node')) return '#ff4757'
  if (flags.includes('vpn_provider')) return '#ff6b35'
  if (flags.includes('known_hosting_provider')) return '#ffa502'
  return hop.hop_index === 0 ? '#ff4757' : '#4fc3f7'
}

function createDivIcon(color, index) {
  return L.divIcon({
    html: `<div style="
      width:28px; height:28px; border-radius:50%;
      background:${color}22; border:2px solid ${color};
      display:flex; align-items:center; justify-content:center;
      color:${color}; font-size:11px; font-weight:700;
      font-family:'JetBrains Mono',monospace;
      box-shadow:0 0 10px ${color}50;
    ">${index}</div>`,
    className: '',
    iconSize: [28, 28],
    iconAnchor: [14, 14],
    popupAnchor: [0, -16],
  })
}

export default function GeoTraceMap({ originTrace = [] }) {
  const mapRef = useRef(null)
  const mapInstanceRef = useRef(null)

  const geoHops = originTrace.filter(h => h.lat && h.lon && !h.is_private)

  useEffect(() => {
    if (!mapRef.current || geoHops.length === 0) return

    const init = async () => {
      if (!L) {
        L = (await import('leaflet')).default
        // Fix default icon paths
        delete L.Icon.Default.prototype._getIconUrl
        L.Icon.Default.mergeOptions({
          iconUrl: 'https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon.png',
          iconRetinaUrl: 'https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon-2x.png',
          shadowUrl: 'https://unpkg.com/leaflet@1.9.4/dist/images/marker-shadow.png',
        })
      }

      // Destroy previous map
      if (mapInstanceRef.current) {
        mapInstanceRef.current.remove()
        mapInstanceRef.current = null
      }

      const map = L.map(mapRef.current, {
        center: [20, 0],
        zoom: 2,
        zoomControl: true,
        attributionControl: false,
      })

      // Dark tile layer
      L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        maxZoom: 19,
      }).addTo(map)

      mapInstanceRef.current = map

      const latlngs = []

      geoHops.forEach((hop, i) => {
        const color = getMarkerColor(hop)
        const icon = createDivIcon(color, hop.hop_index)
        const ll = [hop.lat, hop.lon]
        latlngs.push(ll)

        const flags = (hop.threat_flags || []).map(f =>
          `<span style="background:${THREAT_COLORS[f]||'#4fc3f7'}22;color:${THREAT_COLORS[f]||'#4fc3f7'};padding:2px 6px;border-radius:4px;font-size:10px;">${f}</span>`
        ).join(' ')

        L.marker(ll, { icon }).addTo(map).bindPopup(`
          <div style="font-family:'JetBrains Mono',monospace;min-width:220px;">
            <div style="font-weight:700;font-size:13px;margin-bottom:8px;color:${color}">
              Hop ${hop.hop_index} — ${hop.is_private ? 'Private' : 'Public'}
            </div>
            <div style="font-size:12px;line-height:1.8">
              <b>IP:</b> ${hop.ip || 'N/A'}<br/>
              <b>Location:</b> ${hop.city || '?'}, ${hop.country || '?'}<br/>
              <b>ISP:</b> ${hop.isp || 'Unknown'}<br/>
              <b>ASN:</b> ${hop.asn || 'N/A'}<br/>
              ${flags ? `<div style="margin-top:6px">${flags}</div>` : ''}
            </div>
          </div>
        `, { maxWidth: 280, className: 'dark-popup' })
      })

      // Draw polyline connecting hops
      if (latlngs.length > 1) {
        L.polyline(latlngs, {
          color: '#4fc3f7',
          weight: 2,
          opacity: 0.5,
          dashArray: '6 6',
        }).addTo(map)
      }

      // Fit bounds
      if (latlngs.length > 0) {
        map.fitBounds(latlngs.length === 1 ? [[latlngs[0][0]-5, latlngs[0][1]-5],[latlngs[0][0]+5, latlngs[0][1]+5]] : latlngs, { padding: [30, 30] })
      }
    }

    init()

    return () => {
      if (mapInstanceRef.current) {
        mapInstanceRef.current.remove()
        mapInstanceRef.current = null
      }
    }
  }, [originTrace])

  return (
    <div className="card fade-in">
      <div className="card-header">
        <div className="card-title">
          <MapPin size={15} />
          Origin Geolocation Trace
        </div>
        <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
          {geoHops.length} public hop{geoHops.length !== 1 ? 's' : ''} mapped
        </span>
      </div>

      {geoHops.length === 0 ? (
        <div className="empty-state">
          <div className="empty-state-icon">🗺️</div>
          <div className="empty-state-title">No geolocatable hops</div>
          <div className="empty-state-sub">All IPs are private or unresolvable</div>
        </div>
      ) : (
        <div id="geo-trace-map" ref={mapRef} className="map-container" />
      )}
    </div>
  )
}
