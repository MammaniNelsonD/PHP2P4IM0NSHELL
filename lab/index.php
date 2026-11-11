<?php
// Laboratorio php2shell de PHP2P4IM0NSHELL
// Punto LFI deliberado (para CVE-2026-109619) + sesiones PHP reales.
// ARRANQUE DE SESIÓN PRIMERO para evitar "headers already sent".
session_start();

// Mantener la sesión viva en el mismo request: peticiones GET que solo
// son sondeo de progreso también refrescan la cookie PHPSESSID.
// (Sin esto, php -S a veces no envía Set-Cookie en la respuesta.)
if (session_id()) {
    session_write_close();
}

$page = isset($_GET['page']) ? $_GET['page'] : null;
if ($page !== null) {
    // Inclusión vulnerable a propósito: es el escenario del laboratorio.
    include $page;
}

// Evitar que un request sin sesión genere warnings raros en demo.
$phpsessid = session_id() ?: (isset($_COOKIE['PHPSESSID']) ? $_COOKIE['PHPSESSID'] : '');
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="utf-8">
    <title>PHP2P4IM0N LAB</title>
    <style>
        body { background:#050505; color:#00ff41; font-family:monospace; padding:24px; }
        h1 { border-bottom:1px solid #00ff41; padding-bottom:8px; }
        table { border-collapse:collapse; margin-top:12px; }
        td { border:1px solid #1f3f1f; padding:4px 10px; font-size:12px; }
        .k { color:#888; }
    </style>
</head>
<body>
    <h1>PHP2P4IM0N LAB</h1>
    <table>
        <tr><td class="k">PHP</td><td><?php echo PHP_VERSION; ?></td></tr>
        <tr><td class="k">SAPI</td><td><?php echo php_sapi_name(); ?></td></tr>
        <tr><td class="k">memory_limit</td><td><?php echo ini_get('memory_limit'); ?></td></tr>
        <tr><td class="k">post_max_size</td><td><?php echo ini_get('post_max_size'); ?></td></tr>
        <tr><td class="k">upload_progress</td><td><?php echo ini_get('session.upload_progress.enabled'); ?></td></tr>
        <tr><td class="k">save_path</td><td><?php echo ini_get('session.save_path'); ?></td></tr>
        <tr><td class="k">session_id</td><td><?php echo $phpsessid ?: '(sin sesion)'; ?></td></tr>
    </table>
    <form method="post" enctype="multipart/form-data">
        <p><input type="file" name="f"> <button>subir</button></p>
    </form>
</body>
</html>
