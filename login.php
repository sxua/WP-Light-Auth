<?php
	define('IS_AJAX', isset($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest');
	if (IS_AJAX) {
		include('login.class.php');
		$login  = new WP_Light_Auth($_POST['action'],$_POST['data']);
	} else {
		echo 'Direct access denied!';
	}
?>
