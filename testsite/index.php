<?php
// deliberately vulnerable sample site (no DB needed — for live pentest demos)
session_start();
$config_pass = 's3cretpw'; // CRED.002 hardcoded password

if (isset($_GET['page'])) {
    include $_GET['page'];                    // FILE.002 LFI/RFI
}
if (isset($_POST['host'])) {
    echo shell_exec('ping -c 1 ' . $_POST['host']);  // CMD.001 RCE
}
if (isset($_COOKIE['cart'])) {
    $cart = unserialize($_COOKIE['cart']);    // DESER.001 object injection
}
if (isset($_GET['goto'])) {
    header('Location: ' . $_GET['goto']);     // REDIR.001 open redirect
}
$products = [
    ['id' => 1, 'name' => 'First product'],
    ['id' => 2, 'name' => 'Second product'],
];
foreach ($products as $row) {
    echo "<h1>" . $row['name'] . "</h1>";
    echo $_GET['msg'];                        // XSS.001 reflected XSS
}
if (isset($_GET['debug'])) var_dump($_POST);  // DEBUG.001
?>
<p>Welcome back, <?= $_GET['name'] ?></p>      <!-- XSS.003 -->
