const mc = require('flying-squid');
const V = process.env.MCV || '1.18.2';
const PORT = +(process.env.PORT || 25565);
mc.createMCServer({
  motd: 'ShieldWall protected', port: PORT, host: '0.0.0.0', 'max-players': 20, version: V,
  'online-mode': false, worldFolder: 'world', generation: { name: 'diamond_square', options: { worldHeight: 64 } },
  kickTimeout: 120000, plugins: {}, modpe: false, 'view-distance': 3,
  'player-list-text': { header: '', footer: '' },
});
console.log('MC_SERVER_UP port=' + PORT + ' version=' + V);
