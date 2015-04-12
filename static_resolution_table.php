<?php
/*
	This is built-in static resolution table.
	Each name resolution event starts with checking this table. Hosts and IPs listed in this table resolve
	in fastest way possible because no further interaction with external database of remote DNS server is
	performed.
	This table should contain hosts and IP's that require frequent name resolution. All hosts listed in
	this table sould have static IP addresses. For example: your gateway/router, name server, domain
	controller, other servers and devices on your network.
	This table can also be used to return alternative responses for requests to external domains.
	With all appropriate record types, this table can host primary zone for your domain or subdomain.
	Keep in mind that every worker process keeps a separate copy of this table in memory. The number of
	records here should be limited to what you actually need.
	Changes take effect after server restart.
*/

$table = Array(
	'example.tld.' => Array(
		'A' => Array(
			'1.2.3.4' => Array ('ttl' => 5),
			'1.2.3.5' => Array ('ttl' => 5)
			),
		'AAAA'=> Array(
			'2607:f8b0:4002:802::1015' => Array('ttl' => 5),
			'2607:f8b0:4002:802::1016' => Array('ttl' => 5)
			),
		'NS' => Array(
			'ns1.example.tld'   => Array('ttl' => 10800)
			),
		'MX' => Array(
			'smtp.example.tld'  => Array('ttl' => 5,'pri' => 10),
			'mail.example.tld'  => Array('ttl' => 5,'pri' => 20)
			),
		'TXT' => Array(
			0                   => Array('ttl' => 5,
			                             'txt' => 'v=spf1 a mx include:gmail.com -all'
					       ),
			1                   => Array('ttl' => 5,
			                             'txt' => 'This info comes from Cutebind static_resolution_table.php'
					       )
			),
		'SOA'=> Array(
			'ns1.example.tld'   => Array('ttl'        => 10800,
						     'rname'      => 'admin.example.tld',
						     'serial'     => 2014072800,	// must not excede 10 digits
						     'refresh'    => 900,
						     'retry' 	  => 600,
						     'expire'	  => 3600,
						     'minimum-ttl'=> 300,
						)
			)
		),

	// Dont forget A records for all hosts mentioned above
	'ns1.example.tld.' => Array(
		'A' => Array(
			'1.2.3.4' => Array ('ttl' => 5),
			),
		),
	'smtp.example.tld.' => Array(
		'A' => Array(
			'1.2.3.4' => Array ('ttl' => 5),
			),
		),
	'mail.example.tld.' => Array(
		'A' => Array(
			'1.2.3.4' => Array ('ttl' => 5),
			),
		),

	// Website is hosted elsewhere? Use CNAME. Or you can try A record if your site has a dedicated IP.
	'www.example.tld.' => Array(
		'CNAME' => Array(
			'www.example.tld.godaddy.com' => Array ('ttl' => 5)
			),
		),

	// This is example of a PTR (reverse) record.
	'1.2.3.4' => Array(
		'PTR' => Array(
				'example.tld' => Array('ttl' => 10800)
			)
		),
);

// Creating Authority Zone for sbl server.

if( $settings['SBL'] ) {

	$table[''] = Array(
/*		'A' => Array(
			'1.2.3.4' => Array ('ttl' => 5),
			'1.2.3.5' => Array ('ttl' => 5)
			),
		'AAAA'=> Array(
			'2607:f8b0:4002:802::1015' => Array('ttl' => 5),
			'2607:f8b0:4002:802::1016' => Array('ttl' => 5)
			),
		'NS' => Array(
			'ns1.example.tld'   => Array('ttl' => 10800)
			),
		'MX' => Array(
			'smtp.example.tld'  => Array('ttl' => 5,'pri' => 10),
			'mail.example.tld'  => Array('ttl' => 5,'pri' => 20)
			),
		'TXT' => Array(
			0                   => Array('ttl' => 600,
			                             'txt' => 'v=spf1 a mx include:gmail.com -all'
					       )
			),
*/		'SOA'=> Array(
			'sbl.example.tld'  => Array('ttl'		=> 10800,
						     'rname'		=> 'admin.example.tld',
						     'serial'		=> date('YmdH'),	// must not excede 10 digits
						     'refresh'		=> 600,
						     'retry'		=> 600,
						     'expire'		=> 86400,
						     'minimum-ttl'	=> 300,
						)
			),

		'sbl.example.tld.' => Array(
			'NS' => Array(
				'192.168.1.16'	=> Array('ttl' => 300)
			),

			'A' => Array(
				'192.168.1.16'	=> Array ('ttl' => 300)
				),
			),
		);

}

?>
