
<style>
    .registration { background-image: none; }
    #control-panel { margin:20% 0%; }
</style>




<section id="main-content" class="content-area" style="min-height: 595px;">
    <style type="text/css" data-type="vc_shortcodes-custom-css">.vc_custom_1884220365467{background-color: #261F27 !important;padding: 50px 0px 50px 0px !important;}</style>
    <header class="entry-header">
		<div id="vsc_row_ubjpvjwvxl" style="margin-top: -26px;"class=" vc_row wpb_row vc_inner vc_row-fluid page-title vc_custom_1884220365467 dark row" style="" data-token="U48xq"><div class="container">
			
	<div class="vc_col-sm-12 wpb_column column_container ">
		<div class="wpb_wrapper">
			
				<header class="section-title text-center "><h2 style="color: #ffffff; font-family: Fira Sans; font-weight: 400; font-style: normal; ">Dashboard</h2></header>
			
		</div> 
	</div> 

		</div></div>
	</header>
	<div class="container-fluid">

		
Dashboard <a href="/user/subscriptions">Subscriptions</a> <a href="/user/invoices">Invoices</a> <a href="/user/account">Account</a>
        <br><br>
<?php 
    $unifi_shared_is_present == 0;
    $unifi_is_present == 0;
    $unms_is_present == 0;
    $ucrm_is_present == 0;
	$servername = 'redacted';
	$dbname = 'redacted';
	$username = 'redacted';
	$password = 'redacted';

    $current_user = wp_get_current_user();
    $user_login = $current_user->user_login;



// Get active servers

try {
    $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $stmt = $conn->prepare("SELECT * FROM vultr_check WHERE username = :user_login");
    $stmt->bindParam(':user_login', $user_login);
    $stmt->execute();

    // set the resulting array to associative
    $result = $stmt->setFetchMode(PDO::FETCH_ASSOC);
    $vultr_check_result = $stmt->fetchAll();

}
catch(PDOException $e) {
    echo "Error: " . $e->getMessage();
}
$conn = null;


// Get active subsciptions
try {
    $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $stmt = $conn->prepare("SELECT * from wp_users INNER JOIN wp_edd_customers ON wp_users.id=wp_edd_customers.user_id INNER JOIN wp_edd_subscriptions ON wp_edd_customers.id = wp_edd_subscriptions.customer_id WHERE user_login = :user_login AND status = 'active'");
    $stmt->bindParam(':user_login', $user_login);
    $stmt->execute();

	if ($stmt->execute()) {
	    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
	        $active_rows[] = $row;
	    }
	}

}
catch(PDOException $e) {
    echo "Error: " . $e->getMessage();
}
$conn = null;

// Get Vultr Check
try {
    $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $stmt = $conn->prepare("SELECT * from vultr_check");
    $stmt->bindParam(':user_login', $user_login);
    $stmt->execute();

	if ($stmt->execute()) {
	    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
	        $vultr_rows[] = $row;
	    }
	}

	foreach ($active_rows as $active_row) {
		foreach ($vultr_rows as $vultr_row) {
			if ($active_row["id"] == $vultr_row["wp_edd_sub_id"]) {

				$already_built[] = $active_row["id"];
				break;
			}

		}
		

	}
	foreach ($active_rows as $active_row) {
		if (!in_array($active_row["id"], $already_built)) {
			$pending_subs[] = $active_row;
		}
	}
}
catch(PDOException $e) {
    echo "Error: " . $e->getMessage();
}
$conn = null;

if (!empty($pending_subs)) {
	echo "Your server is being built, this will usually take 5-15 minutes. The page will refresh automatically<br><br><b>Check your spam folder!</b> Make sure you are receiving emails from hostifi.net<br>We will send you an email when setup has completed";
}
if (!empty($pending_subs) || !empty($already_built)) {

echo '<table id="edd_user_history"><thead>
  <tr class="edd_purchase_row">

    <th>Server</th>
    <th>Username</th>
    <th>Temp Password</th>
    <th>Subscription</th>
    <th>Status</th>
  </tr></thead><tbody>';

} else {

	echo 'You don\'t have any active subscriptions! <a href="https://hostifi.net/">Subscribe to a plan</a> so that we can build your server for you';
}


foreach ($already_built as $running_server) {

	// Get vultr server info
	try {
		$sub_id = $running_server;

	    $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
	    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	    $stmt = $conn->prepare("SELECT * from vultr_check WHERE wp_edd_sub_id = :sub_id");
	    $stmt->bindParam(':sub_id', $sub_id);
	    $stmt->execute();

		$server_rows = $stmt->fetchAll();

		foreach ($server_rows as $server_row) {
			$port = ":8443";
			$plan = "";
			$plan_cost = '<a href="https://hostifi.net/user/subscriptions">View Subscription</a>';
			$application = "";
			if ($server_row["product_id"] == "5948") {
				$plan = "UniFi Video";
				$port = ":7443";
				$plan_cost = '<a href="https://hostifi.net/user/subscriptions">View Subscription</a>';
				$unifi_video_is_present = 1;
				$application = "UniFi Video Server";
			}
			if ($server_row["product_id"] == "5565") {
				$plan = "UCRM";
				$port = "";
				$plan_cost = '<a href="https://hostifi.net/user/subscriptions">View Subscription</a>';
				$ucrm_is_present = 1;
				$application = "UCRM Server";
			}
			if ($server_row["product_id"] == "3002") {
				$plan = "UniFi";
				$plan_cost = '<a href="https://hostifi.net/user/subscriptions">View Subscription</a>';
				$unifi_shared_is_present = 1;
				$application = "UniFi Site";
			}
			if ($server_row["product_id"] == "2955") {
				$plan = "UniFi";
				$plan_cost = '<a href="https://hostifi.net/user/subscriptions">View Subscription</a>';
				$unifi_shared_is_present = 1;
				$application = "UniFi Site";
			}
			if ($server_row["product_id"] == "2922") {
				$plan = "UniFi";
				$plan_cost = '<a href="https://hostifi.net/user/subscriptions">View Subscription</a>';
				$unifi_is_present = 1;
				$application = "UniFi Server";
			}
			if ($server_row["product_id"] == "5324") {
				$plan = "UniFi";
				$plan_cost = '<a href="https://hostifi.net/user/subscriptions">View Subscription</a>';
				$unifi_is_present = 1;
				$application = "UniFi Server";
			}
			if ($server_row["product_id"] == "5327") {
				$plan = "UniFi";
				$plan_cost = '<a href="https://hostifi.net/user/subscriptions">View Subscription</a>';
				$unifi_is_present = 1;
				$application = "UniFi Server";
			}
			if ($server_row["product_id"] == "5500" or $server_row["product_id"] == "6213" or $server_row["product_id"] == "6211" or $server_row["product_id"] == "17420" or $server_row["product_id"] == "17418" or $server_row["product_id"] == "17416" or $server_row["product_id"] == "17414") {
				$plan = "UNMS";
				$plan_cost = '<a href="https://hostifi.net/user/subscriptions">View Subscription</a>';
				$port = "";
				$application = "UNMS Server";
				$unms_is_present = 1;
			}
			echo '<td><a href="https://' . $server_row["server_name"] . $port . '" target="_blank">https://' . $server_row["server_name"] . $port . '</a></td>';
			echo '<td>' . $server_row["username"] . '</td>';
			echo '<td>' . $server_row["admin_pw"] . '</td>';
			echo '<td>' . $plan_cost . '</td>';
			echo '<td>Provisioned</td>';

			echo '</tr>';
		}

	}
	catch(PDOException $e) {
	    echo "Error: " . $e->getMessage();
	}
	$conn = null;

}

foreach ($pending_subs as $pending_server) {
	$port = ":8443";
	if ($server_row["product_id"] == "5948") {
		$plan = "UniFi-Video-VPS-10";
		$port = ":7443";
		$plan_cost = '<a href="https://hostifi.net/user/subscriptions">$19/month</a>';
		$unifi_video_is_present = 1;
		$application = "UniFi Video Server";
	}
	if ($server_row["product_id"] == "5565") {
		$plan = "UCRM-VPS";
		$port = "";
		$plan_cost = '<a href="https://hostifi.net/user/subscriptions">$19/month</a>';
		$ucrm_is_present = 1;
		$application = "UCRM Server";
	}
	if ($server_row["product_id"] == "3002") {
		$plan = "UniFi-Shared-25";
		$plan_cost = '<a href="https://hostifi.net/user/subscriptions">$0/month</a>';
		$unifi_shared_is_present = 1;
		$application = "FREE UniFi Site";
	}
	if ($server_row["product_id"] == "2955") {
		$plan = "UniFi-Shared-25";
		$plan_cost = '<a href="https://hostifi.net/user/subscriptions">$0/month</a>';
		$unifi_shared_is_present = 1;
		$application = "FREE UniFi Site";
	}
	if ($server_row["product_id"] == "2922") {
		$plan = "UniFi-VPS-125";
		$plan_cost = '<a href="https://hostifi.net/user/subscriptions">$19/month</a>';
		$unifi_is_present = 1;
		$application = "UniFi Server";
	}
	if ($server_row["product_id"] == "5324") {
		$plan = "UniFi-VPS-250";
		$plan_cost = '<a href="https://hostifi.net/user/subscriptions">$29/month</a>';
		$unifi_is_present = 1;
		$application = "UniFi Server";
	}
	if ($server_row["product_id"] == "5327") {
		$plan = "UniFi-VPS-500";
		$plan_cost = '<a href="https://hostifi.net/user/subscriptions">$49/month</a>';
		$unifi_is_present = 1;
		$application = "UniFi Server";
	}
	if ($server_row["product_id"] == "5500") {
		$plan = "UNMS-VPS-125";
		$plan_cost = '<a href="https://hostifi.net/user/subscriptions">$19/month</a>';
		$port = "";
		$application = "UNMS Server";
		$unms_is_present = 1;
	}
	echo '<tr class="edd_user_history"><td>--</td>';

	echo '<td>--</td>';
	echo '<td>--</td>';
	echo '<td>--</td>';

	echo '<td>Building</td>';

	echo '</tr>';
	
}

if (!empty($pending_subs) || !empty($already_built)) {

	echo "</tbody></table>"; 
}
if (!empty($pending_subs)) {
	$should_refresh = 1;
} else {
	$should_refresh = 0;
}

?>
</div>
<?php
if (!empty($already_built) and $unifi_video_is_present == 1) {
?>
<div>

<center>
<h1>Congratulations! Your UniFi Video Server is ready</h1>
<p>Use the username and temp password to login to the server (link above)</p>
<h2>Getting Started</h2>
<h3>To migrate your existing cameras or add new cameras to HostiFi:</h3>
<p>
<br>1. Log in to your UniFi Video server using the URL, username, and temp password above
<br>2. Download the <a href="https://chrome.google.com/webstore/detail/ubiquiti-device-discovery/hmpigflbjeapnknladcfphgkemopofig?hl=en">Ubiquiti Discovery Tool Chrome Extension</a>
<br>3. For each camera discovered on your network, log into it over HTTP
<br>Default password is ubnt/ubnt, but if the camera has been adopted to an existing server you will need to get the camera password
<br>from the NVR under Settings > Camera Settings > Camera Password, or factory reset it using the reset button
<br>4. After logging into a camera, set the mode to UniFi Video, and the server to the name of your HostiFi UniFi Video server (above)
<br>No port number or https prefix is needed. Also, set the Adoption Token which you will need to get from the HostiFi server under Settings > Camera Settings
<br>5. The camera will contact the HostiFi server
<br>6. The camera may upgrade its firmware and should become connected after that
</p>
<h3>Troubleshooting tips:</h3>
<br><b>Camera connects but is stuck "Upgrading"</b>
<br>If you do not see the "Adoption Token" input in the camera's web interface, you will need to upgrade the firmware before you can connect it to HostiFi
<br>The easiest way to fix that is to <a href="https://www.ubnt.com/download/unifi-video/">download UniFi Video version 3.8.3</a> locally and adopt the camera to it
<br>It will then upgrade its firmware, and you can Unmanage it from the local server, then connect it to the HostiFi server
<br>
<br>
</center>
</div>
<?php
}
?>
<?php
if (!empty($already_built) and $unifi_is_present == 1) {
?>
<div>

<center>
<h1>Congratulations! Your UniFi Server is ready</h1>
<p>Use the username and temp password to login to the server (link above)</p>
<h2>Getting Started</h2>
<h3>To migrate your existing controller to HostiFi:</h3>
<p>
<br>1. Use the <a href="https://help.ubnt.com/hc/en-us/articles/115002869188-UniFi-Migrating-Sites-with-Site-Export-Wizard">site import/export wizard</a> (easy to use, only takes a few minutes per site!)
<br>2. Migrate each site from your old controller to your new controller
<br>3. Devices are managed by your controller!
<br>
</p>
<h3>To add new network devices to the controller:</h3>
<p>
<br>1. Download the <a href="https://chrome.google.com/webstore/detail/ubiquiti-device-discovery/hmpigflbjeapnknladcfphgkemopofig?hl=en">Ubiquiti Discovery Tool Chrome Extension</a>
<br>2. Follow the <a href="https://www.youtube.com/watch?v=yZw43qdDaY8">"Layer 3 adoption"</a> steps to connect your UniFi devices
<br>3. Devices are managed by your controller!
<br>
<h3>Troubleshooting tips:</h3>
<br>1. Use http://your-hostifi-server.hostifi.net<b>:8080/inform</b> as the set-inform address when adding new network devices
<br>2. Make sure to set-inform a second time after Adopting the device in the controller
<br>3. Use ubnt/ubnt, the factory default username/password, as the set-inform credentials when using the Discovery Tool
<br>
<br>If you need any help or have feedback on what we can improve please contact us: <a href="mailto:support@hostifi.net">support@hostifi.net</a>
</p>
<br>
<br>
<br>
<br>
</center>
</div>
<?php
}
?>
<?php
if (!empty($already_built) and $unifi_shared_is_present == 1) {
?>
<div>

<center>
<h1>Congratulations! Your UniFi Site is ready</h1>
<p>Use the username and temp password to login to the server (link above)</p>
<h2>Getting Started</h2>
<h3>To migrate your existing controller to HostiFi:</h3>
<p>
<br>The site migration wizard is only available on the paid plans.
<br>However, you can still migrate an existing site by manually copying over your network settings,
<br>then set-inform your devices to connect to the new server. See the section below on how to add devices.
<br>
<h3>To add new network devices to the controller:</h3>
<p>
<br>1. Download the <a href="https://chrome.google.com/webstore/detail/ubiquiti-device-discovery/hmpigflbjeapnknladcfphgkemopofig?hl=en">Ubiquiti Discovery Tool Chrome Extension</a>
<br>2. Follow the <a href="https://www.youtube.com/watch?v=yZw43qdDaY8">"Layer 3 adoption"</a> steps to connect your UniFi devices
<br>3. Devices are managed by your new server!
<br>
<h3>Troubleshooting tips:</h3>
<br>1. Use http://your-hostifi-server.hostifi.net<b>:8080/inform</b> as the set-inform address when adding new network devices
<br>2. Make sure to set-inform a second time after we Adopt the device to your site
<br>3. Use ubnt/ubnt, the factory default username/password, as the set-inform credentials when using the Discovery Tool if the devices are new or factory reset
<br>
<br>If you need any help or have feedback on what we can improve please contact us: <a href="mailto:support@hostifi.net">support@hostifi.net</a>
</p>
<br>
<br>
<br>
<br>
</center>
</div>
<?php
}
?>
<?php
if (!empty($already_built) and $unms_is_present == 1) {
?>
<div>

<center>
<h1>Congratulations! Your UNMS Server is ready</h1>
<p>Use the username and temp password to login to the server (link above)</p>
<h2>Getting Started</h2>
<h3>To add new network devices to UNMS:</h3>
<br>1. Follow one of the methods here: <a href="https://help.ubnt.com/hc/en-us/articles/115015772548-UNMS-The-UNMS-Key-and-the-Device-Registration-Process">https://help.ubnt.com/hc/en-us/articles/115015772548-UNMS-The-UNMS-Key-and-the-Device-Registration-Process</a>
<br>
<h3>To migrate existing UNMS to HostiFi UNMS:</h3>
<br>1. You'll need to make sure that all of your existing UNMS devices are connected via DNS and not IP address
<br>2. Backup UNMS and restore to HostiFi UNMS
<br>3. Update your UNMS DNS record to point to HostiFi UNMS IP address (you can get this by pinging your HostiFi server address)

<br>
<br>If you need any help or have feedback on what we can improve please contact us: <a href="mailto:support@hostifi.net">support@hostifi.net</a>
</p>
<br>
<br>
<br>
<br>
</center>
</div>
<?php
}
?>

<?php
if (!empty($already_built) and $ucrm_is_present == 1) {
?>
<div>

<center>
<h1>Congratulations! Your UCRM Server is ready</h1>
<p>Use the username and temp password to login to the server (link above)</p>
<h2>Getting Started</h2>
<h3>To migrate existing UCRM to HostiFi UCRM:</h3>
<br>1. Follow the migration steps here <a href="https://help.ubnt.com/hc/en-us/articles/225876948-UCRM-Backup-and-Migration">https://help.ubnt.com/hc/en-us/articles/225876948-UCRM-Backup-and-Migration</a>
<br>2. After migration, please create superadmin "hostifi" and send the password to <a href="mailto:support@hostifi.net">support@hostifi.net</a>. We use this account for our nightly backup script
<br>
<h3>To migrate existing airCRM to HostiFi UCRM:</h3>
<br>1. Follow the airCRM to UCRM migration steps here <a href="https://help.ubnt.com/hc/en-us/articles/222450347-UCRM-How-to-Migrate-from-airCRM-to-UCRM">https://help.ubnt.com/hc/en-us/articles/222450347-UCRM-How-to-Migrate-from-airCRM-to-UCRM</a>
<br>2. After migration, please create superadmin "hostifi" and send the password to <a href="mailto:support@hostifi.net">support@hostifi.net</a>. We use this account for our nightly backup script
<br>
<br>If you need any help or have feedback on what we can improve please contact us: <a href="mailto:support@hostifi.net">support@hostifi.net</a>
</p>
<br>
<br>
<br>
<br>
</center>
</div>
<?php
}
?>

<script type="text/javascript">
var should_refresh = <?php echo $should_refresh; ?>;
if (should_refresh == 1) {
	window.setTimeout(function(){ document.location.reload(true); }, 15000);
}

</script>
</section>