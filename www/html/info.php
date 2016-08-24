<?php
error_log("_SERVER:");
foreach($_SERVER as $key => $val) {
    error_log("    $key => $val");
}

phpinfo();
?>
