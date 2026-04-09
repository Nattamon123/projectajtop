import geoip from 'geoip-lite';

/**
 * 🗺️ โมดูลระบุพิกัดที่ตั้ง (Geolocation Locator)
 * 
 * หน้าที่ของไฟล์นี้คือรับ IP Address เข้ามา (เช่น 8.8.8.8)
 * แล้วนำไปเทียบกับฐานข้อมูล geoip-lite เพื่อแปลงเป็นพิกัด (ละติจูด, ลองจิจูด), ประเทศ, และเมือง
 * แยกไฟล์ออกมาต่างหากเพื่อให้โครงสร้างอ่านง่ายและหาเจอได้รวดเร็ว
 */

export function getGeoLocation(ipAddress) {
  // ฟังก์ชัน lookup ของ geoip-lite จะช่วยค้นหาที่ตั้งจากเลข IP
  const geo = geoip.lookup(ipAddress);
  
  if (geo) {
    return {
      country: geo.country, // ประเทศ (เช่น 'TH', 'US')
      city: geo.city || 'Unknown', // ชื่อเมือง
      latitude: geo.ll[0], // เส้นรุ้ง (Latitude)
      longitude: geo.ll[1], // เส้นแวง (Longitude)
    };
  }

  // หากหาไม่เจอ (เช่น IP ภายในเครือข่ายวงแลน 192.168.x.x) ให้คืนค่าพิกัดกลาง
  return null;
}
