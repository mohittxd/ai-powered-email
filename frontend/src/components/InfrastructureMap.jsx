import React, { useEffect } from 'react';
import { MapContainer, TileLayer, Marker, Popup, Polyline } from 'react-leaflet';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';
import { MapPin, Info } from 'lucide-react';

const createIcon = (type) => {
  let color = '#4fc3f7'; // default relay / hop
  if (type === 'origin') color = '#ff4757';
  if (type === 'destination') color = '#2ed573';
  
  return L.divIcon({
    html: `<div style="
      width: 16px; height: 16px; border-radius: 50%;
      background: ${color}; border: 2px solid #080d14;
      box-shadow: 0 0 8px ${color};
    "></div>`,
    className: '',
    iconSize: [16, 16],
    iconAnchor: [8, 8]
  });
};

export default function InfrastructureMap({ forensics }) {
  if (!forensics || !forensics.received_chain) return null;

  const earliestIp = forensics.earliest_observed_public_sender_ip;
  const chain = forensics.received_chain;
  
  // Extract hops that have valid geolocation
  const geoHops = [];
  chain.forEach((hop, idx) => {
    const geo = hop.geolocation;
    if (geo && geo.latitude !== undefined && geo.longitude !== undefined) {
      const isOrigin = hop.source_ip === earliestIp && earliestIp !== null;
      const isDest = idx === 0 && !isOrigin; // idx 0 is the most recent (destination) in our reversed chain
      let type = 'relay';
      if (isOrigin) type = 'origin';
      else if (isDest) type = 'destination';
      
      geoHops.push({
        ...hop,
        geo,
        type,
        lat: geo.latitude,
        lon: geo.longitude
      });
    }
  });

  if (geoHops.length === 0) {
    return (
      <div className="card fade-in">
        <div className="card-header">
          <div className="card-title"><MapPin size={16} /> Observed Infrastructure</div>
        </div>
        <div className="empty-state" style={{ padding: '24px' }}>
          No geolocatable infrastructure observed.
        </div>
      </div>
    );
  }

  // Path coordinates
  // The chain is newest-first (idx 0 is destination). 
  // To draw path from origin to destination, we should reverse geoHops
  const pathCoordinates = [...geoHops].reverse().map(h => [h.lat, h.lon]);
  
  // Calculate center
  const centerLat = geoHops.reduce((sum, h) => sum + h.lat, 0) / geoHops.length;
  const centerLon = geoHops.reduce((sum, h) => sum + h.lon, 0) / geoHops.length;

  return (
    <div className="card fade-in">
      <div className="card-header">
        <div className="card-title"><MapPin size={16} /> Observed Infrastructure</div>
      </div>
      
      <div style={{ height: 400, borderRadius: '8px', overflow: 'hidden', border: '1px solid var(--border-subtle)', position: 'relative' }}>
        <MapContainer center={[centerLat, centerLon]} zoom={2} style={{ height: '100%', width: '100%', background: '#0a111c' }}>
          <TileLayer
            url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
            attribution='&copy; <a href="https://carto.com/">CARTO</a>'
          />
          
          {pathCoordinates.length > 1 && (
            <Polyline positions={pathCoordinates} color="#4fc3f7" weight={2} dashArray="5, 10" opacity={0.6} />
          )}

          {geoHops.map((hop, idx) => (
            <Marker key={idx} position={[hop.lat, hop.lon]} icon={createIcon(hop.type)}>
              <Popup className="dark-popup">
                <div style={{ fontFamily: "'Inter', sans-serif", minWidth: 200, color: '#080d14' }}>
                  <div style={{ fontWeight: 700, fontSize: '13px', marginBottom: 8, borderBottom: '1px solid #ccc', paddingBottom: 4 }}>
                    {hop.type === 'origin' ? 'Earliest Observed Public IP' : hop.type === 'destination' ? 'Destination/Relay' : 'Observed email hop'}
                  </div>
                  <div style={{ fontSize: '12px', lineHeight: 1.6 }}>
                    <div><strong>IP:</strong> <span style={{ fontFamily: 'monospace' }}>{hop.source_ip}</span></div>
                    <div><strong>Location:</strong> {hop.geo.city || 'Unknown'}, {hop.geo.region || 'Unknown'}, {hop.geo.country || 'Unknown'}</div>
                    <div><strong>ISP:</strong> {hop.geo.isp || 'Unknown'}</div>
                    <div><strong>ASN:</strong> {hop.geo.asn || 'Unknown'}</div>
                  </div>
                </div>
              </Popup>
            </Marker>
          ))}
        </MapContainer>
        
        {/* Legend */}
        <div style={{
          position: 'absolute', bottom: 20, right: 20, zIndex: 1000, 
          background: 'rgba(13, 22, 33, 0.9)', padding: '12px', borderRadius: '8px',
          border: '1px solid var(--border-subtle)', backdropFilter: 'blur(4px)',
          fontSize: '0.75rem', display: 'flex', flexDirection: 'column', gap: '8px'
        }}>
          <div style={{ fontWeight: 600, marginBottom: '4px', display: 'flex', alignItems: 'center', gap: '4px' }}>
            <Info size={12} /> Legend
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <div style={{ width: '12px', height: '12px', borderRadius: '50%', background: '#ff4757' }}></div>
            <span>Earliest observed public IP</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <div style={{ width: '12px', height: '12px', borderRadius: '50%', background: '#4fc3f7' }}></div>
            <span>Observed email hop</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <div style={{ width: '12px', height: '12px', borderRadius: '50%', background: '#2ed573' }}></div>
            <span>Destination/relay</span>
          </div>
        </div>
      </div>
    </div>
  );
}
