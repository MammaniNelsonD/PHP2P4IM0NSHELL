<img width="128" height="128" alt="icon" src="https://github.com/user-attachments/assets/c2db33b4-e9a4-4888-a1f3-964130c83e89" />


# 🐘 PHP2P4IM0NSHELL v1.2

🧩 Extensión de navegador (Manifest V3) para auditar la clase **php2shell**
(`CVE-2026-109618`, `CVE-2026-109619`, `CVE-2026-10961x`) desde Chrome/Edge.
Misma estética y estructura que `React2P4IM0Nshell`: CMD_CENTER + RECON,
terminal Alpine v86 embebida y generador de reverse shells.

> ⚠️ Solo laboratorios propios o con autorización escrita. La extensión no
> descubre ni ataca objetivos por sí sola: opera sobre la pestaña activa.

---

<img width="1904" height="832" alt="photo_5161645817952144640_w" src="https://github.com/user-attachments/assets/c7e9bf65-008e-40d1-a1e6-b67bf4455af3" />
<img width="1904" height="884" alt="photo_5161645817952144638_w" src="https://github.com/user-attachments/assets/f090c259-4946-423f-ae54-662f9d6c28a4" />
<img width="1904" height="900" alt="photo_5161645817952144639_w" src="https://github.com/user-attachments/assets/c5732cc6-cc61-4715-85e3-d29d364b48f5" />


## 📥 Instalación

1. `chrome://extensions` → activar **Modo de desarrollador**.
2. **Cargar descomprimida** → seleccionar esta carpeta.
3. Abrir el objetivo y pulsar el icono. Badge: `PHP` (firma), `VULN`
   (condiciones), `PWN` (ejecución confirmada).

🔐 Permisos: `activeTab`, `scripting`, `storage`, `cookies` + host `http/https`.
`cookies` se usa solo para leer `PHPSESSID` cuando es `HttpOnly`, necesario
para deducir `/tmp/sess_<id>`.

---

## ⚙️ Qué hace de verdad cada módulo

| 🧩 Módulo | ⚡ Ejecuta | 🔎 Evidencia que exige |
|---|---|---|
| `RECONOCIMIENTO_PASIVO` | DOM + cabeceras + cookies; tabla de versiones corregidas (8.5.12 / 8.4.27 / 8.3.36 / 8.2.35; EOL 8.1↓) | `X-Powered-By`, `Server`, `PHPSESSID` |
| `SONDA_ACTIVA` | Multipart con `PHP_SESSION_UPLOAD_PROGRESS` + sondeo del JSON de progreso; prueba del separador coma en `Content-Type` | `start_time` / `bytes_processed` en la respuesta |
| `CVE-2026-109619` | Inyecta `<?php ... shell_exec($_REQUEST['c']) ...?>` como key del progreso (queda en `/tmp/sess_<id>`), barre 48 rutas LFI y ejecuta el comando | marcador `P4IM0N<< ... >>P4IM0N` en el cuerpo |
| `CVE-2026-10961x` | Escalera OOM 2/8/32 MB | `Allowed memory size of N bytes exhausted` (fuga real de `memory_limit`) |
| `CVE-2026-109618` | Pre-flight real (5 checks) + handoff al PoC `poc_109618.py`. El UAF se ejecuta fuera del navegador con sockets crudos; la extension valida requisitos y entrega comando calibrado. | checklist + comando + ruta script |

### 🧠 Por qué el UAF no se ejecuta desde el navegador

El chain de CVE-2026-109618 son 4 stages sobre sockets crudos: rotación de worker,
fuga de heap vía OOM + `Set-Cookie`, fuga de `libphp`, y `fake HashTable` → `zif_system`.
`fetch()` no puede emitir multipart byte-exacto con cabeceras duplicadas, ni
`chunked`, ni leer `Set-Cookie` (prohibido por la especificación). Simularlo
daría falsos positivos, así que la extensión valida los requisitos y entrega el
comando calibrado al PoC oficial. El `CVE-2026-10961x` real usa cabeceras
duplicadas de 6 bytes que `Headers` colapsa; la escalera OOM que ejecuta la
extension revela la superficie, pero el exploit de 52x se lanza con el PoC del
repositorio, no desde el navegador.

---

## 🧪 Laboratorio (Windows, php -S)

El lab incluye `lab/php.ini` y `lab/index.php`. Tu servidor real debe:

- arrancar sesión primero (`session_start()` antes de emitir HTML),
- responder la cookie `Set-Cookie: PHPSESSID=...` en la pestaña (o que la pestaña la guarde para que `document.cookie` la vea),
- tener `session.save_path` consistente con donde encuentras los `sess_*`.

### 🚀 Iniciar laboratorio

Para un lab rápido con el built-in de PHP:

```bash
# desde la raíz del repo:
cd lab
php -S 127.0.0.1:8080 -c php.ini
```

🎯 Objetivo: `http://127.0.0.1:8080/index.php`.

Solo CVE-2026-109619 necesita un punto LFI real: `index.php` ya incluye
`?page=...`. Con el `php.ini` del lab, las sesiones van a
`lab/sessions/sess_<id>` y el popup predetermina `.sessions` cuando el
objetivo es local.

🐳 Builds calibrados del PoC (UAF): `php:8.4.26-apache` / `php:8.5.11-apache`
(Debian bookworm). En otros builds el UAF necesita `--zif-offset` y
`--dtor-offset`.

---

## 🔬 Flujo de demo real (sin simulaciones)

1. 🌐 Abre el objetivo en Chrome/Edge.
2. 🟢 Pulsa el icono de la extensión: badge `PHP` + `VULN` una vez que la sonda confirma `session.upload_progress` + versión vulnerable.
3. 🖥️ En CMD_CENTER:
   - `CVE-2026-109619` → comando `id` → primera pulsación muestra aviso, segunda ejecuta.
   - `CVE-2026-10961x` → escalera OOM que revela `memory_limit` y `post_max_size`.
   - `CVE-2026-109618` → pulsa la opción para ver el pre-flight (5/5 checks) y el comando calibrado del PoC.
4. 📂 Si el popup predetermina mal la ruta de sesión, escribe `.sessions` en el campo `save_path` y repite.

---

## ⚠️ Límites conocidos

- No hay sockets crudos ni `chunked`: nada de UAF, ni bypass de
  `Content-Length`, ni amplificación por cabeceras duplicadas.
- `document.cookie` no ve cookies `HttpOnly`; de ahí el permiso `cookies`.
- Páginas `chrome://`, Web Store y PDF no admiten content script (badge
  `OFFLINE`, es esperado).
- El barrido LFI es heurístico (48 peticiones, 70 ms de pausa); si el
  parámetro de inclusión no está en la lista, la sesión queda envenenada
  pero no habrá ejecución. Se declara como tal, sin inventar éxito.
- Si `php -S` no devuelve `Set-Cookie` en alguna pestaña, el módulo de
  sesión se queja claramente y pide recargar antes de inyectar; no
  inventa éxito ni sesión.


- No hay sockets crudos ni `chunked`: nada de UAF, ni bypass de
  `Content-Length`, ni amplificación por cabeceras duplicadas.
- `document.cookie` no ve cookies `HttpOnly`; de ahí el permiso `cookies`.
- Páginas `chrome://`, Web Store y PDF no admiten content script (badge
  `OFFLINE`, es esperado).
- El barrido LFI es heurístico (48 peticiones, 70 ms de pausa); si el
  parámetro de inclusión no está en la lista, la sesión queda envenenada
  pero no habrá ejecución. Se declara como tal, sin inventar éxito.


---

## 🧰 Motor de pruebas (Engine Harness)

`tools/engine-harness.cjs` ejecuta el `content.js` real (el mismo archivo que
carga Chrome) contra la URL del lab, emulando `chrome`, `document` y
`location`. Sirve para demostrar que los módulos funcionan sin depender de la
interfaz:

```bash
node tools/engine-harness.cjs
```

### 📊 Salida verificada contra el laboratorio (PHP 8.4.26, Apache, Debian)

| 🧩 Módulo | 📋 Resultado real |
|---|---|
| `RECONOCIMIENTO_PASIVO` | `PHP 8.4.26 -> VULNERABLE`; lee configuraci\u00f3n y fija `lfi_param=page`, `save_path=data/sessions` |
| `CVE-2026-109619` | `exito=true` → `uid=258625556(...) gid=1001(freebuff)` |
| `CVE-2026-10961x` | `exito=true` → `Allowed memory size of 16777216 bytes exhausted` |
| `CVE-2026-109618` | Pre-flight `5/5` + comando calibrado del PoC `poc_109618.py` (el UAF se lanza fuera del navegador) |

El motor lee primero el manifiesto del laboratorio (`/health.php`) para conocer
el par\u00e1metro LFI y el `save_path`; si el POST de inyección devuelve otro `sid`,
adopta ese archivo en vez de buscar el de la cookie. Solo declara ejecución
cuando el marcador aparece en la respuesta.

---

## 📁 Estructura del proyecto

```text
manifest.json   MV3 (v1.2.0)
background.js   cookies (HttpOnly) + badges
content.js      motor: fingerprint, sonda, OOM, sesión+LFI, pre-flight
popup.html/js   UI cyberpunk: CMD_CENTER / RECON
popup.css       tema P4IM0N (#00ff41, Share Tech Mono)
images/icon.*   icono
tools/          scripts de apoyo: poc_109618.py (PoC CVE-2026-109618)
engine-harness.cjs   ARNÉS de pruebas (ejecuta content.js real contra el lab)
```

---

## ⚖️ Descargo de responsabilidad

**PHP2P4IM0NSHELL** es una herramienta desarrollada exclusivamente con fines educativos, de investigación y auditoría de seguridad informática autorizada.

Su uso está destinado únicamente a:

- 🧪 Laboratorios personales y entornos de pruebas controlados.
- 🖥️ Sistemas, aplicaciones e infraestructuras de propiedad del usuario.
- 🔐 Evaluaciones de seguridad realizadas con autorización expresa del propietario del sistema.

🚫 **No se autoriza ni se promueve el uso de esta herramienta contra sistemas, servidores, aplicaciones o infraestructuras de terceros sin el consentimiento previo y explícito de sus responsables.**

El usuario es el único responsable de garantizar que dispone de los permisos legales necesarios antes de utilizar esta herramienta.

Los autores y colaboradores no se hacen responsables del uso indebido, daños, interrupciones, pérdidas de información o consecuencias legales derivadas de su utilización.

**Al utilizar PHP2P4IM0NSHELL, aceptás que toda actividad realizada con la herramienta es bajo tu propia responsabilidad y dentro de los límites de la legislación aplicable.**

---

<p align="center">
  🐘 <b>PHP2P4IM0NSHELL v1.2</b><br>
  🔬 Research • Pentesting • Security Auditing<br>
  ⚡ Built for controlled environments
</p>
