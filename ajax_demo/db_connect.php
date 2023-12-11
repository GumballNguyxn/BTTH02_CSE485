<?php
try {
    $conn = new PDO("mysql:host=localhost;dbname=BTTH02_1", "root", "");
} catch (Exception $e) {
    echo $e->getMessage();
}
?>