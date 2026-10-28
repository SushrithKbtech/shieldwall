const mineflayer = require('mineflayer');
const mc = require('minecraft-protocol');
const HOST = process.env.H || '192.168.77.1', PORT = +(process.env.P || 25565), V = process.env.MCV || '1.18.2';
const t0 = Date.now();
const log = o => console.log(JSON.stringify({ dt: +((Date.now() - t0) / 1000).toFixed(2), ...o }));
const bot = mineflayer.createBot({ host: HOST, port: PORT, username: 'Player1', version: V, auth: 'offline' });
bot.once('spawn', () => log({ ev: 'spawn' }));
bot.on('kicked', r => log({ ev: 'kicked', r: String(r).slice(0, 50) }));
bot.on('end', r => log({ ev: 'end', r: String(r).slice(0, 30) }));
bot.on('error', e => log({ ev: 'error', r: e.message.slice(0, 50) }));
setInterval(() => {
  const s = Date.now();
  mc.ping({ host: HOST, port: PORT, version: V, closeTimeout: 2000 }, (err, res) => {
    if (err) log({ ev: 'ping', ok: false }); else log({ ev: 'ping', ok: true, ms: Date.now() - s });
  });
}, 1000);
