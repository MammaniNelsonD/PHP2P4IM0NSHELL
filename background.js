// PHP2P4IM0NSHELL - Controlador de Fondo (Service Worker) v1.1
// Autor: P4IM0N
//  1. Lee la cookie PHPSESSID real (incluye HttpOnly: document.cookie no la ve)
//  2. Pinta el badge de estado del objetivo (PHP / VULN / PWN)
//  3. Limpia el badge al navegar

const BADGES = {
    php:    { texto: 'PHP',  color: '#FF6A00' },
    vuln:   { texto: 'VULN', color: '#FFAE00' },
    pwn:    { texto: 'PWN',  color: '#FF003C' },
    limpio: { texto: '',     color: '#00FF41' }
};

function pintarBadge(tabId, tipo) {
    const cfg = BADGES[tipo] || BADGES.limpio;
    try {
        chrome.action.setBadgeBackgroundColor({ tabId, color: cfg.color });
        chrome.action.setBadgeText({ tabId, text: cfg.texto });
    } catch (e) { /* pestana cerrada */ }
}

chrome.runtime.onMessage.addListener((solicitud, emisor, responder) => {

    // ---- Cookie de sesion (funciona con HttpOnly) ----
    if (solicitud.accion === 'leer_cookie_sesion') {
        const nombre = solicitud.nombre || 'PHPSESSID';
        const url = solicitud.url;

        if (!url || !/^https?:/i.test(url)) {
            responder({ valor: null, error: 'URL no http(s): la API de cookies no aplica.' });
            return false;
        }

        chrome.cookies.get({ url, name: nombre }, (cookie) => {
            if (chrome.runtime.lastError) {
                responder({ valor: null, error: chrome.runtime.lastError.message });
                return;
            }
            responder({
                valor: cookie ? cookie.value : null,
                httpOnly: cookie ? cookie.httpOnly : null,
                secure: cookie ? cookie.secure : null,
                dominio: cookie ? cookie.domain : null,
                ruta: cookie ? cookie.path : null
            });
        });
        return true;
    }

    // ---- Inventario de cookies del objetivo ----
    if (solicitud.accion === 'listar_cookies') {
        const url = solicitud.url;
        if (!url || !/^https?:/i.test(url)) {
            responder({ cookies: [], error: 'URL no http(s).' });
            return false;
        }
        chrome.cookies.getAll({ url }, (cookies) => {
            if (chrome.runtime.lastError) {
                responder({ cookies: [], error: chrome.runtime.lastError.message });
                return;
            }
            responder({
                cookies: (cookies || []).map((c) => ({
                    nombre: c.name,
                    httpOnly: c.httpOnly,
                    secure: c.secure,
                    mismoSitio: c.sameSite,
                    sesion: c.session
                }))
            });
        });
        return true;
    }

    if (solicitud.accion === 'marcar_php_detectado') {
        const tabId = (emisor.tab && emisor.tab.id) || solicitud.tabId;
        if (typeof tabId === 'number') pintarBadge(tabId, 'php');
        return false;
    }

    if (solicitud.accion === 'marcar_vulnerable') {
        const tabId = (emisor.tab && emisor.tab.id) || solicitud.tabId;
        if (typeof tabId === 'number') pintarBadge(tabId, 'vuln');
        return false;
    }

    if (solicitud.accion === 'actualizar_insignia') {
        const tabId = (emisor.tab && emisor.tab.id) || solicitud.tabId;
        if (typeof tabId === 'number') pintarBadge(tabId, 'pwn');
        return false;
    }

    if (solicitud.accion === 'resetear_insignia') {
        const tabId = (emisor.tab && emisor.tab.id) || solicitud.tabId;
        if (typeof tabId === 'number') pintarBadge(tabId, 'limpio');
        return false;
    }

    return false;
});

chrome.tabs.onUpdated.addListener((tabId, info) => {
    if (info.status === 'loading') pintarBadge(tabId, 'limpio');
});

chrome.runtime.onInstalled.addListener(() => {
    console.log('[P4IM0N:PHP] PHP2P4IM0NSHELL v1.1 instalada. Solo laboratorios autorizados.');
});
