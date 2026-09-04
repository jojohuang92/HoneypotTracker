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
import type { GeoPin, LiveAttackEvent, Sensor } from "../../types";
import { formatTimestamp, formatNumber } from "../../utils/formatters";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
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

/** Beyond this many overlapping pins a spiderfy fan wraps into an unreadable
 *  ring, so those clusters open a scrollable source list instead. */
const SPIDERFY_LIMIT = 6;

const PANEL_WIDTH = 268;
const PANEL_HEIGHT = 316;

/** The slice of Leaflet.markercluster's cluster API used here — the plugin
 *  ships no type declarations of its own. */
interface MarkerCluster extends L.Marker {
  getBounds(): L.LatLngBounds;
  getAllChildMarkers(): L.Marker[];
  zoomToBounds(options?: L.FitBoundsOptions): void;
  spiderfy(): void;
}

interface ClusterList {
  pins: GeoPin[];
  left: number;
  top: number;
}

function positionKey(lat: number, lng: number) {
  return `${lat},${lng}`;
}

function clamp(value: number, min: number, max: number) {
  return Math.min(Math.max(value, min), Math.max(min, max));
}

/** Header for the source list: the shared place name when every pin sits in
 *  the same one, which is the usual case for a stack of overlapping pins. */
function listHeading(pins: GeoPin[]) {
  const [first] = pins;
  const sameSpot = pins.every(
    (pin) => pin.city === first.city && pin.country_code === first.country_code,
  );
  if (!sameSpot) return `${pins.length} locations`;
  return [first.city, first.country_name ?? first.country_code].filter(Boolean).join(", ") ||
    "Unknown location";
}

interface ClusterLayerProps {
  pins: GeoPin[];
  scale: ThreatScale;
  onPinClick?: (pin: GeoPin) => void;
}

/** Attack pins, clustered. Clicking a cluster zooms in while that still
 *  separates it; once the pins are stacked on one spot, a dense cluster opens
 *  a list of its sources rather than fanning them around the map. */
function ClusterLayer({ pins, scale, onPinClick }: ClusterLayerProps) {
  const map = useMap();
  const [list, setList] = useState<ClusterList | null>(null);
  const [expanded, setExpanded] = useState<number | null>(null);
  const panelRef = useRef<HTMLDivElement>(null);

  /** Child markers only report coordinates, so index the pins by position to
   *  recover the data behind a clicked cluster. */
  const byPosition = useMemo(() => {
    const index = new Map<string, GeoPin[]>();
    for (const pin of pins) {
      const key = positionKey(pin.latitude, pin.longitude);
      const bucket = index.get(key);
      if (bucket) bucket.push(pin);
      else index.set(key, [pin]);
    }
    return index;
  }, [pins]);

  const close = useCallback(() => {
    setList(null);
    setExpanded(null);
  }, []);

  useEffect(() => {
    map.on("movestart zoomstart click", close);
    return () => {
      map.off("movestart zoomstart click", close);
    };
  }, [map, close]);

  useEffect(() => {
    if (!list) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") close();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [list, close]);

  // Clicks and wheel scrolls inside the panel must not pan or zoom the map.
  useEffect(() => {
    const el = panelRef.current;
    if (!el) return;
    L.DomEvent.disableClickPropagation(el);
    L.DomEvent.disableScrollPropagation(el);
  }, [list]);

  const handleClusterClick = useCallback(
    (event: L.LeafletMouseEvent) => {
      const cluster = event.layer as MarkerCluster;
      const bounds = cluster.getBounds();

      // A cluster covering real ground still breaks apart by zooming, which
      // stays the more useful answer.
      if (
        !bounds.getNorthEast().equals(bounds.getSouthWest()) &&
        map.getZoom() < map.getMaxZoom()
      ) {
        cluster.zoomToBounds({ padding: [40, 40] });
        return;
      }

      const children = cluster.getAllChildMarkers();
      if (children.length <= SPIDERFY_LIMIT) {
        cluster.spiderfy();
        return;
      }

      const seen = new Set<string>();
      const listed: GeoPin[] = [];
      for (const marker of children) {
        const { lat, lng } = marker.getLatLng();
        const key = positionKey(lat, lng);
        if (seen.has(key)) continue;
        seen.add(key);
        listed.push(...(byPosition.get(key) ?? []));
      }
      if (listed.length === 0) return;
      listed.sort((a, b) => b.count - a.count);

      const size = map.getSize();
      const point = map.latLngToContainerPoint(cluster.getLatLng());
      setExpanded(null);
      setList({
        pins: listed,
        left: clamp(point.x + 20, 8, size.x - PANEL_WIDTH - 8),
        top: clamp(point.y - 16, 8, size.y - PANEL_HEIGHT - 8),
      });
    },
    [map, byPosition],
  );

  return (
    <>
      <MarkerClusterGroup
        chunkedLoading
        maxClusterRadius={50}
        spiderfyOnMaxZoom={false}
        zoomToBoundsOnClick={false}
        showCoverageOnHover={false}
        iconCreateFunction={createClusterIcon}
        onClick={handleClusterClick}
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

      {list && (
        <div
          ref={panelRef}
          role="dialog"
          aria-label="Attack sources in this cluster"
          className="absolute z-[1200] flex flex-col overflow-hidden rounded-lg border border-gray-800 bg-gray-950/95 shadow-xl shadow-black/40 backdrop-blur-md"
          style={{ left: list.left, top: list.top, width: PANEL_WIDTH, maxHeight: PANEL_HEIGHT }}
        >
          <div className="flex items-center justify-between gap-2 border-b border-gray-800 px-3 py-2">
            <div className="min-w-0">
              <div className="truncate text-xs font-semibold text-gray-100">
                {listHeading(list.pins)}
              </div>
              <div className="text-[10px] uppercase tracking-wider text-gray-500">
                {list.pins.length} sources
              </div>
            </div>
            <button
              type="button"
              onClick={close}
              aria-label="Close source list"
              className="shrink-0 rounded px-1.5 py-0.5 text-gray-500 hover:bg-gray-800 hover:text-gray-200"
            >
              &#215;
            </button>
          </div>

          <ul className="overflow-y-auto overscroll-contain">
            {list.pins.map((pin, i) => {
              const { color } = gradeFor(pin.count, scale);
              const isOpen = expanded === i;
              return (
                <li key={`${pin.latest_src_ip}-${i}`} className="border-b border-gray-900 last:border-0">
                  <button
                    type="button"
                    aria-expanded={isOpen}
                    onClick={() => {
                      setExpanded(isOpen ? null : i);
                      onPinClick?.(pin);
                    }}
                    className="flex w-full items-center gap-2 px-3 py-1.5 text-left hover:bg-gray-800/60"
                  >
                    <span
                      className="h-2 w-2 shrink-0 rounded-full border border-white/40"
                      style={{ background: color, boxShadow: `0 0 6px ${color}99` }}
                    />
                    <span className="min-w-0 flex-1 truncate font-mono text-[11px] text-gray-200">
                      {pin.latest_src_ip ?? "Unknown IP"}
                    </span>
                    <span
                      className="font-mono text-[11px] font-semibold tabular-nums"
                      style={{ color }}
                    >
                      {formatNumber(pin.count)}
                    </span>
                  </button>

                  {isOpen && (
                    <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 bg-gray-900/50 px-3 pb-2 pt-1 text-[11px]">
                      <dt className="text-gray-500">Location</dt>
                      <dd className="truncate text-gray-300">
                        {[pin.city, pin.country_name].filter(Boolean).join(", ") || "Unknown"}
                      </dd>
                      <dt className="text-gray-500">Last seen</dt>
                      <dd className="text-gray-300">
                        {pin.latest_timestamp ? formatTimestamp(pin.latest_timestamp) : "\u2014"}
                      </dd>
                      <dt className="text-gray-500">Last event</dt>
                      <dd className="truncate font-mono text-gray-300">
                        {pin.latest_event_id?.replace("cowrie.", "") ?? "\u2014"}
                      </dd>
                    </dl>
                  )}
                </li>
              );
            })}
          </ul>
        </div>
      )}
    </>
  );
}

interface AttackMapProps {
  pins: GeoPin[];
  onPinClick?: (pin: GeoPin) => void;
  lastEvent?: LiveAttackEvent | null;
  containerWidth?: number;
  /** Sensors to mark as attack destinations. */
  sensors?: Sensor[];
}

/** Sensor marker: a diamond, so a defender is never confused with an
 *  attacker pin. Coordinates arrive pre-coarsened by the API, so a sensor
 *  published at country precision cannot be pinpointed from this map. */
function createSensorIcon(status: Sensor["status"]) {
  const color = status === "online" ? "#22d3ee" : "#64748b";
  return L.divIcon({
    className: "",
    html: `<div style="
      width: 14px;
      height: 14px;
      background: ${color};
      border: 2px solid rgba(255,255,255,0.9);
      transform: rotate(45deg);
      box-shadow: 0 0 10px ${color};
    "></div>`,
    iconSize: [14, 14],
    iconAnchor: [7, 7],
  });
}

const WORLD_BOUNDS: L.LatLngBoundsExpression = [[-85, -180], [85, 180]];

export default function AttackMap({
  pins,
  onPinClick,
  lastEvent,
  containerWidth,
  sensors = [],
}: AttackMapProps) {
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
      {/* Esri Dark Gray Canvas: key-free dark basemap. Native tiles stop at z16,
          so Leaflet upscales beyond that instead of fetching placeholder tiles. */}
      <TileLayer
        attribution='Tiles &copy; <a href="https://www.esri.com/">Esri</a> &mdash; Esri, DeLorme, NAVTEQ'
        url="https://services.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}"
        className="basemap-dim"
        maxNativeZoom={16}
        noWrap={true}
      />
      {/* Place labels above the basemap but below markers, dimmed so pins stay dominant */}
      <Pane name="labels" style={{ zIndex: 210, pointerEvents: "none" }}>
        <TileLayer
          url="https://services.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Reference/MapServer/tile/{z}/{y}/{x}"
          maxNativeZoom={16}
          noWrap={true}
          opacity={0.55}
        />
      </Pane>

      <ZoomControl position="bottomright" />

      <MapResizer width={containerWidth ?? 0} />
      {lastEvent && <NewAttackAnimator lastEvent={lastEvent} />}

      {sensors
        .filter((s) => s.latitude != null && s.longitude != null)
        .map((sensor) => (
          <Marker
            key={`sensor-${sensor.sensor_id}`}
            position={[sensor.latitude as number, sensor.longitude as number]}
            icon={createSensorIcon(sensor.status)}
            zIndexOffset={1000}
          >
            <Tooltip direction="top" offset={[0, -8]} opacity={0.95}>
              <span style={{ fontFamily: "monospace", fontSize: "12px" }}>
                {sensor.label} · {sensor.status}
              </span>
            </Tooltip>
            <Popup>
              <div className="min-w-[180px] text-sm">
                <div className="font-bold text-white mb-1">{sensor.label}</div>
                <div className="space-y-1 text-gray-300">
                  <div>
                    <span className="text-gray-500">Status:</span> {sensor.status}
                  </div>
                  <div>
                    <span className="text-gray-500">Protocols:</span>{" "}
                    {sensor.protocols.join(", ") || "—"}
                  </div>
                  <div>
                    <span className="text-gray-500">24h attacks:</span>{" "}
                    <span className="font-bold text-orange-400">
                      {sensor.attempts_24h.toLocaleString()}
                    </span>
                  </div>
                  {sensor.location_precision === "country" && (
                    <div className="text-[11px] text-gray-500">
                      Position shown at country level
                    </div>
                  )}
                </div>
              </div>
            </Popup>
          </Marker>
        ))}

      <ClusterLayer pins={pins} scale={scale} onPinClick={onPinClick} />
    </MapContainer>
  );
}
