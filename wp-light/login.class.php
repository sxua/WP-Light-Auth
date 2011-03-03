<?php
	include('../wp-load.php'); // path to WP's wp-load.php file
	require_once(ABSPATH.WPINC.'/registration.php'); // required for WP registration functions
	header('content-type:application/json;charset=utf-8'); // yes, we need JSON

	class WP_Light_Auth {
		function __construct($action_type,$data) {
			$this->return['error'] = true; // defining error by default
			
			if ($action_type === 'login') {
				if (!empty($data['user_email']) && !empty($data['user_password'])) {
					$data = self::prepare_data('wp',$data);
					$this->login($data);
				} else {
					$this->empty_fields();
				}
			}
			
			elseif ($action_type === 'logout') {
				$this->logout();
			}
			
			elseif ($action_type === 'register') {
				if (!empty($data['user_email']) && !empty($data['user_password']) && !empty($data['user_firstname']) && !empty($data['user_lastname'])) {
					$data = self::prepare_data('wp',$data);
					$this->register($data);
				} else {
					$this->empty_fields();
				}
			}
			
			elseif ($action_type === 'check_vk') {
				$app_secret = 'YOUR_VK_APP_SECRET'; // VK App secret
				$valid_keys = array('expire','mid','secret','sid','sig');
				$app_id = 'YOUR_VK_APP_ID'; // VK App ID
				$app_cookie = $_COOKIE['vk_app_'.$app_id];
				$auth = self::check_opensig($app_secret,$valid_keys,$app_cookie);
				if ($auth) {
					$data = self::prepare_data('vk',$data);
					$this->proceed_check($data);
				}
			}
			
			elseif ($action_type === 'check_fb') {
				$app_secret = 'YOUR_DB_APP_SECRET'; // FB App secret
				$valid_keys = array('access_token','base_domain','expires','secret','session_key','sig','uid');
				$app_id = 'YOUR_FB_APP_ID'; // FB App ID
				$app_cookie = trim(stripslashes($_COOKIE['fbs_'.$app_id]),"\x22"); // there's "dirty" json in cookie
				$auth = self::check_opensig($app_secret,$valid_keys,$app_cookie);
				if ($auth) {
					$data = self::prepare_data('fb',$data);
					$this->proceed_check($data);
				}
			}
			
			else {
				$this->return['error_message'] = '<p>Unknown function</p>';
			}
			return print json_encode($this->return);
		}
		
		private function login($data) {
			$user = wp_signon(array('user_login' => $data['user_login'],'user_password' => $data['user_pass'],'remember' => true));
			if (is_wp_error($user)) {
				$this->return['error_message'] = '<p>'.$user->get_error_message().'</p>';
			} else {
				setcookie('wp-light-logged-in',$user->data->display_name,time()+3600,'/',$_SERVER['HTTP_HOST']);
				$this->return['error'] = false;
			}
		}
		
		private function logout() {
			wp_logout();
			setcookie('wp-light-logged-in','0',mktime(0,0,0,1,1,1970),'/',$_SERVER['HTTP_HOST']);
			$this->return['error'] = false;
		}
		
		private function register($data) {
			$user = username_exists($data['user_login']);
			if (!$user) {
				$user = wp_insert_user($data);
				if (is_wp_error($user)) {
					$this->return['error_message'] = '<p>'.$user->get_error_message().'</p>';
				} else {
					if (is_int($user)) {
						if (isset($data['avatar'])) {
							update_usermeta($user,'open_avatar',$data['avatar']);
						}
						$this->login($data);
						$this->return['error'] = false;
					}
				}
			} else {
				$this->return['error_message'] = '<p>User with that name already exist.</p>';
			}
		}
		
		private function proceed_check($data) {
			$user = username_exists($data['user_login']);
			if (!$user) {
				$this->register($data);
			} else {
				$this->login($data);
			}
		}

		protected static function check_opensig($secret,$keys,$cookie) {
			return ($cookie) ? self::check_sig($cookie,$secret,$keys) : false;
		}
		
		protected static function prepare_data($from,$data) { // creating an universal object with user data
			if ($from === 'vk') {
				$new_data = array(
					'user_login' => 'vk_'.$data['mid'],
					'user_nicename' => 'vk_'.$data['mid'],
					'user_url' => $data['user']['href'],
					'display_name' => $data['user']['first_name'].' '.$data['user']['last_name'],
					'first_name' => $data['user']['first_name'],
					'last_name' => $data['user']['last_name'],
					'user_pass' => $data['mid'].'_vk_user_password',
					'user_email' => 'vk_'.$data['mid'].'@'.$_SERVER['HTTP_HOST'], // maybe something else?! because, we can't retrieve user email from VK
					'avatar' => $data['photo']
				);
			} elseif ($from === 'fb') {
				$new_data = array(
					'user_login' => 'fb_'.$data['uid'],
					'user_nicename' => 'fb_'.$data['uid'],
					'user_url' => $data['profile_url'],
					'display_name' => $data['first_name'].' '.$data['last_name'],
					'first_name' => $data['first_name'],
					'last_name' => $data['last_name'],
					'user_pass' => $data['uid'].'_fb_user_password',
					'user_email' => $data['email'],
					'avatar' => $data['pic_square']
				);
			} elseif ($from === 'wp') {
				$new_data = array(
					'user_login' => self::email_to_login($data['user_email']),
					'user_nicename' => self::email_to_login($data['user_email']),
					'user_url' => '',
					'display_name' => $data['user_firstname'].' '.$data['user_lastname'],
					'first_name' => $data['user_firstname'],
					'last_name' => $data['user_lastname'],
					'user_pass' => $data['user_password'],
					'user_email' => $data['user_email']
				);
			}
			return $new_data;
		}
		
		protected static function email_to_login($email) { // using e-mail as login
			return str_replace('@','_at_',$email);
		}
		
		protected static function check_sig($data,$secret,$keys) { // universal sig checker for fb and vk
			$session = array();
			$session_data = explode('&',$data,10);
			foreach ($session_data as $pair) {
				list($key,$value) = explode('=',$pair,2);
				if (empty($key) || empty($value) || !in_array($key,$keys)) {
					continue;
				}
				$session[$key] = $value;
			}
			foreach ($keys as $key) {
				if (!isset($session[$key])) return false;
			}
			ksort($session);
			$sign = '';
			foreach ($session as $key => $value) {
				if ($key != 'sig') {
					$sign .= $key.'='.$value;
				}
			}
			$sign .= $secret;
			$expire = (isset($session['expire'])) ? $session['expire'] : $session['expires']; // difference between fb and vk cookie
			return ($session['sig'] == md5($sign) && $expire > time()) ? true : false;
		}
		
		private function empty_fields() {
			$this->return['error_message'] = '<p>Please, fill each form field.</p>';
		}
	}
?>
