import {
  MapContainer,
  TileLayer,
  Marker,
  Popup,
  Tooltip,
  useMap,
  ZoomControl,
  Pane,
} from "react-leaflet";
import MarkerClusterGroup from "react-leaflet-cluster";
import L from "leaflet";
import "leaflet/dist/leaflet.css";
import type { GeoPin, LiveAttackEvent } from "../../types";
import { formatTimestamp, formatNumber } from "../../utils/formatters";
import { useEffect, useMemo } from "react";
import { computeThreatScale, gradeFor, compactCount, type ThreatScale } from "./threatScale";

function createPinIcon(count: number, scale: ThreatScale) {
  const { color, size } = gradeFor(count, scale);
  return L.divIcon({
    className: "",
    html: `<span class="attack-pin" style="--pin:${color}"></span>`,
    iconSize: [size, size],
    iconAnchor: [size / 2, size / 2],
  });
}

function createClusterIcon(cluster: { getChildCount: () => number }) {
  const count = cluster.getChildCount();
  const grade = count >= 100 ? " attack-cluster--high" : count >= 25 ? " attack-cluster--mid" : "";
  const size = count >= 100 ? 44 : count >= 25 ? 38 : 32;
  const label = compactCount(count);
  return L.divIcon({
    className: "",
    html: `<div class="attack-cluster${grade}"><span>${label}</span></div>`,
    iconSize: [size, size],
    iconAnchor: [size / 2, size / 2],
  });
}

const PING_ICON = L.divIcon({
  className: "",
  html: '<span class="attack-ping"><i></i></span>',
  iconSize: [14, 14],
  iconAnchor: [7, 7],
});

interface NewAttackAnimatorProps {
  lastEvent: LiveAttackEvent | null;
}

function NewAttackAnimator({ lastEvent }: NewAttackAnimatorProps) {
  const map = useMap();

  useEffect(() => {
    if (lastEvent?.latitude == null || lastEvent?.longitude == null) return;

    const ping = L.marker([lastEvent.latitude, lastEvent.longitude], {
      icon: PING_ICON,
      interactive: false,
      keyboard: false,
    }).addTo(map);
    const timer = setTimeout(() => map.removeLayer(ping), 2200);

    return () => {
      clearTimeout(timer);
      map.removeLayer(ping);
    };
  }, [lastEvent, map]);

  return null;
}

function MapResizer({ width }: { width: number }) {
  const map = useMap();
  useEffect(() => {
    map.invalidateSize();
  }, [width, map]);
  return null;
}

interface AttackMapProps {
  pins: GeoPin[];
  onPinClick?: (pin: GeoPin) => void;
  lastEvent?: LiveAttackEvent | null;
  containerWidth?: number;
}

const WORLD_BOUNDS: L.LatLngBoundsExpression = [[-85, -180], [85, 180]];

export default function AttackMap({ pins, onPinClick, lastEvent, containerWidth }: AttackMapProps) {
  const scale = useMemo(() => computeThreatScale(pins), [pins]);

  return (
    <MapContainer
      center={[22, 0]}
      zoom={2}
      minZoom={2}
      maxZoom={18}
      maxBounds={WORLD_BOUNDS}
      maxBoundsViscosity={1.0}
      className="h-full w-full"
      zoomControl={false}
      scrollWheelZoom={true}
    >
      <TileLayer
        attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors &copy; <a href="https://carto.com/attributions">CARTO</a>'
        url="https://{s}.basemaps.cartocdn.com/dark_nolabels/{z}/{x}/{y}{r}.png"
        noWrap={true}
      />
      {/* Place labels above the basemap but below markers, dimmed so pins stay dominant */}
      <Pane name="labels" style={{ zIndex: 210, pointerEvents: "none" }}>
        <TileLayer
          url="https://{s}.basemaps.cartocdn.com/dark_only_labels/{z}/{x}/{y}{r}.png"
          noWrap={true}
          opacity={0.55}
        />
      </Pane>

      <ZoomControl position="bottomright" />

      <MapResizer width={containerWidth ?? 0} />
      {lastEvent && <NewAttackAnimator lastEvent={lastEvent} />}

      <MarkerClusterGroup
        chunkedLoading
        maxClusterRadius={50}
        spiderfyOnMaxZoom
        showCoverageOnHover={false}
        iconCreateFunction={createClusterIcon}
      >
        {pins.map((pin, i) => (
          <Marker
            key={`${pin.latitude}-${pin.longitude}-${i}`}
            position={[pin.latitude, pin.longitude]}
            icon={createPinIcon(pin.count, scale)}
            eventHandlers={{
              click: () => onPinClick?.(pin),
            }}
          >
            <Tooltip direction="top" offset={[0, -8]} opacity={1}>
              <span className="font-mono text-xs">
                {[pin.city, pin.country_code].filter(Boolean).join(", ") || "Unknown"}
                {" · "}
                <strong>{formatNumber(pin.count)}</strong>
              </span>
            </Tooltip>
            <Popup>
              <div className="min-w-[220px] text-sm">
                <div className="flex items-center justify-between gap-3 border-b border-gray-700/60 pb-2 mb-2">
                  <span className="font-semibold text-gray-100">
                    {[pin.city, pin.country_name].filter(Boolean).join(", ") || "Unknown location"}
                  </span>
                  {pin.country_code && (
                    <span className="shrink-0 rounded border border-gray-600/60 bg-gray-800 px-1.5 py-0.5 font-mono text-[10px] tracking-wider text-gray-300">
                      {pin.country_code}
                    </span>
                  )}
                </div>
                <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5 text-xs">
                  <dt className="text-gray-500">Source IP</dt>
                  <dd className="font-mono text-gray-200">{pin.latest_src_ip}</dd>
                  <dt className="text-gray-500">Attacks</dt>
                  <dd
                    className="font-mono font-semibold tabular-nums"
                    style={{ color: gradeFor(pin.count, scale).color }}
                  >
                    {formatNumber(pin.count)}
                  </dd>
                  <dt className="text-gray-500">Last seen</dt>
                  <dd className="text-gray-300">
                    {pin.latest_timestamp ? formatTimestamp(pin.latest_timestamp) : "—"}
                  </dd>
                  <dt className="text-gray-500">Last event</dt>
                  <dd className="font-mono text-gray-300">
                    {pin.latest_event_id?.replace("cowrie.", "") ?? "—"}
                  </dd>
                </dl>
              </div>
            </Popup>
          </Marker>
        ))}
      </MarkerClusterGroup>
    </MapContainer>
  );
}
