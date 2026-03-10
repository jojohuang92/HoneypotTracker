import { MapContainer, TileLayer, Marker, Popup, useMap } from "react-leaflet";
import MarkerClusterGroup from "react-leaflet-cluster";
import L from "leaflet";
import "leaflet/dist/leaflet.css";
import type { GeoPin, Attempt } from "../../types";
import { formatTimestamp, intentColor } from "../../utils/formatters";
import { useEffect } from "react";

// Fix default marker icons in bundled builds
import iconUrl from "leaflet/dist/images/marker-icon.png";
import iconShadowUrl from "leaflet/dist/images/marker-shadow.png";
import iconRetinaUrl from "leaflet/dist/images/marker-icon-2x.png";

L.Icon.Default.mergeOptions({
  iconUrl,
  iconRetinaUrl,
  shadowUrl: iconShadowUrl,
});

function createPinIcon(count: number) {
  let color = "#3b82f6"; // blue
  let size = 10;
  if (count > 20) {
    color = "#ef4444"; // red
    size = 16;
  } else if (count > 10) {
    color = "#f97316"; // orange
    size = 14;
  } else if (count > 5) {
    color = "#eab308"; // yellow
    size = 12;
  }

  return L.divIcon({
    className: "",
    html: `<div style="
      width: ${size}px;
      height: ${size}px;
      background: ${color};
      border: 2px solid rgba(255,255,255,0.8);
      border-radius: 50%;
      box-shadow: 0 0 ${size}px ${color}80;
    "></div>`,
    iconSize: [size, size],
    iconAnchor: [size / 2, size / 2],
  });
}

interface NewAttackAnimatorProps {
  lastEvent: Attempt | null;
}

function NewAttackAnimator({ lastEvent }: NewAttackAnimatorProps) {
  const map = useMap();

  useEffect(() => {
    if (lastEvent?.latitude && lastEvent?.longitude) {
      const circle = L.circleMarker([lastEvent.latitude, lastEvent.longitude], {
        radius: 20,
        color: "#ef4444",
        fillColor: "#ef4444",
        fillOpacity: 0.4,
        weight: 2,
        className: "attack-pulse",
      }).addTo(map);

      setTimeout(() => map.removeLayer(circle), 2000);
    }
  }, [lastEvent, map]);

  return null;
}

interface AttackMapProps {
  pins: GeoPin[];
  onPinClick?: (pin: GeoPin) => void;
  lastEvent?: Attempt | null;
}

export default function AttackMap({ pins, onPinClick, lastEvent }: AttackMapProps) {
  return (
    <MapContainer
      center={[20, 0]}
      zoom={2}
      minZoom={2}
      maxZoom={18}
      className="h-full w-full"
      zoomControl={true}
      scrollWheelZoom={true}
    >
      <TileLayer
        attribution='&copy; <a href="https://carto.com/">CARTO</a>'
        url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
      />

      {lastEvent && <NewAttackAnimator lastEvent={lastEvent} />}

      <MarkerClusterGroup
        chunkedLoading
        maxClusterRadius={50}
        spiderfyOnMaxZoom
        showCoverageOnHover={false}
      >
        {pins.map((pin, i) => (
          <Marker
            key={`${pin.latitude}-${pin.longitude}-${i}`}
            position={[pin.latitude, pin.longitude]}
            icon={createPinIcon(pin.count)}
            eventHandlers={{
              click: () => onPinClick?.(pin),
            }}
          >
            <Popup>
              <div className="min-w-[200px] text-sm">
                <div className="font-bold text-white mb-1">
                  {pin.country_name || "Unknown"}
                  {pin.country_code && (
                    <span className="ml-1 text-gray-400 font-normal">
                      ({pin.country_code})
                    </span>
                  )}
                </div>
                <div className="space-y-1 text-gray-300">
                  <div>
                    <span className="text-gray-500">IP:</span>{" "}
                    <span className="font-mono">{pin.latest_src_ip}</span>
                  </div>
                  <div>
                    <span className="text-gray-500">Attacks:</span>{" "}
                    <span className="font-bold text-orange-400">{pin.count}</span>
                  </div>
                  <div>
                    <span className="text-gray-500">Latest:</span>{" "}
                    {pin.latest_timestamp && formatTimestamp(pin.latest_timestamp)}
                  </div>
                  <div>
                    <span className="text-gray-500">Type:</span>{" "}
                    {pin.latest_event_id?.replace("cowrie.", "")}
                  </div>
                </div>
              </div>
            </Popup>
          </Marker>
        ))}
      </MarkerClusterGroup>
    </MapContainer>
  );
}
