/**
 * 🗺️ โมดูลดูแลแผนที่โลก (Geolocation Map)
 * 
 * ไฟล์นี้ถูกแยกออกมาเพื่อจัดการแผนที่โดยเฉพาะ (ใช้ไลบรารี Leaflet.js)
 * หน้าที่คือวาดแผนที่โลก และนำพิกัดดาวเทียม (Latitude, Longitude) ที่เซิร์ฟเวอร์หามาได้ ไปปักหมุดลงบนแผนที่
 */

let map;
let markersLayer;

// 1️⃣ ฟังก์ชันสร้างแผนที่ (Initialize Map)
export function initMap(containerId) {
  // ตรวจสอบว่าในหน้า HTML มีกล่องสำหรับวาดแผนที่ไหม
  const mapElement = document.getElementById(containerId);
  if (!mapElement) return;

  // สร้างแผนที่ Leaflet และกำหนดจุดเริ่มต้นไว้ที่ตรงกลางโลก ซูมระดับ 2
  map = L.map(containerId, {
    center: [20, 0], 
    zoom: 2,
    zoomControl: false, // ปิดปุ่มซูมเพื่อความสะอาดตา
    attributionControl: false // ปิดข้อความลายน้ำด้านล่าง
  });

  // ใส่พื้นหลังเป็นแผนที่โลกโทนสีเข้ม (Dark Matter CartoDB) ให้เข้ากับหน้าตา Dashboard สีดำ
  L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
    maxZoom: 19
  }).addTo(map);

  // เตรียม Layer พิเศษ เอาไว้ใส่จุดปักพิกัด (Markers)
  markersLayer = L.layerGroup().addTo(map);
}

// 2️⃣ ฟังก์ชันแสดงจุดบนแผนที่ (Plot Packets)
export function plotPackets(packets) {
  if (!map || !markersLayer) return;

  // วนลูปอ่านข้อมูลทีละแพ็กเก็ต
  for (const p of packets) {
    if (p.geo && p.geo.latitude && p.geo.longitude) {
      
      // สร้างจุดวงกลมสีฟ้าอ่อนขนาดเล็ก (รัศมี 3 เมตรจำลอง)
      const circle = L.circleMarker([p.geo.latitude, p.geo.longitude], {
        color: '#06b6d4',      // สีขอบ (Cyan)
        fillColor: '#06b6d4',  // สีพื้น
        fillOpacity: 0.7,
        radius: 3,
        weight: 1
      });

      // ใส่ข้อความ Tooltip เมื่อเอาเมาส์ไปชี้จะได้รู้ IP และประเทศ
      circle.bindTooltip(`<b>IP:</b> ${p.srcIp} <br> <b>ประเทศ:</b> ${p.geo.country} - ${p.geo.city}`);

      // เอาจุดไปแปะบนแผนที่
      circle.addTo(markersLayer);

      // กฎการลบจุด: เพื่อไม่ให้หน้าจอรก เราจะให้จุดค่อยๆ หายไปเองใน 3 วินาที
      setTimeout(() => {
        markersLayer.removeLayer(circle);
      }, 3000);
    }
  }
}
