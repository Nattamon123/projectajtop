import geoip from 'geoip-lite';
console.log(JSON.stringify(geoip.lookup('1.1.1.1'), null, 2));
console.log(JSON.stringify(geoip.lookup('8.8.8.8'), null, 2));
