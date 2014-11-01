CREATE SCHEMA IF NOT EXISTS cuteresolve;

USE cuteresolve;

CREATE TABLE IF NOT EXISTS `peers` (
  `peer_id` varchar(40) NOT NULL,
  `external_ip` int(11) NOT NULL,
  `internal_ip` int(11) NOT NULL,
  `ctime` int(11) NOT NULL,
  PRIMARY KEY  (`peer_id`),
  KEY `external_ip` (`external_ip`,`internal_ip`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `blacklist` (
  `ip` varchar(15) NOT NULL,
  `date_added` datetime DEFAULT CURRENT_TIMESTAMP,
  `source` varchar(80) DEFAULT NULL,
  PRIMARY KEY (`ip`),
  KEY `ix_date_added` (`date_added`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1 COMMENT='Mail will always be rejected from these IP addresses.';

CREATE TABLE IF NOT EXISTS `whitelist` (
  `ip` varchar(15) NOT NULL,
  `date_added` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `date_expires` datetime DEFAULT NULL COMMENT 'Record expires and will be removed after this date. Optional. Leave NULL for no exiration.',
  `notes` varchar(255) DEFAULT NULL COMMENT 'A note to indicate reason why this IP is whitelisted.',
  PRIMARY KEY (`ip`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1 COMMENT='Mail will always be accepted from these IP addresses.';
