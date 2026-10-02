<?php
define('DBHOST', getenv('DB_HOST') ?: 'localhost');
define('DBUSER', getenv('DB_USER') ?: 'root');
define('DBPASS', getenv('DB_PASSWORD') ?: 'antonio3304');
define('DBNAME', getenv('DB_NAME') ?: 'infrastructure');
define('ENABLE_OAUTH', true);
define('FILES_FOLDER', getenv('FILES_FOLDER') ?: 'C:\wamp64\www\csweb\files');
define('INTERNAL_FILES_FOLDER', getenv('INTERNAL_FILES_FOLDER') ?: 'C:\wamp64\www\csweb\files_csweb');
define('DEFAULT_TIMEZONE', 'UTC');
define('MAX_EXECUTION_TIME', '300');
define('API_URL', getenv('API_URL') ?: 'http://localhost/csweb/api/');
define('CSWEB_APP_SECRET', getenv('CSWEB_APP_SECRET') ?: '5b68b4663fd83dcd171a6b59ce89158650d3d91978f076660273b51db014f712');
define('CSWEB_LOG_LEVEL' , 'error');
define('CSWEB_PROCESS_CASES_LOG_LEVEL', 'error');
?>
